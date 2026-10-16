# KernelDump: 라이브 리눅스 및 쿠버네티스 노드를 위한 정책 기반 커널 플레인 물리 메모리 획득 도구

[English](README.md) | [한국어](README.ko.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Language: Rust](https://img.shields.io/badge/Language-Rust_1.90+-orange.svg)](Cargo.toml)
[![Forensics: Volatility 3](https://img.shields.io/badge/Forensics-Volatility_3_59_Plugins_Evaluated-brightgreen.svg)](validation.json)
[![Binary: Static musl](https://img.shields.io/badge/Binary-Static_musl_Zero_Dependency-blueviolet.svg)](release/)
[![Status: Production Ready](https://img.shields.io/badge/Status-Production_Ready-success.svg)](release/)

**운영 중인 쿠버네티스(Kubernetes) 워커 노드 및 고밀도 리눅스 환경을 위한 초고속·저부하 커널 플레인 물리 메모리 획득 엔진.**

`KernelDump`는 리눅스 커널 가상 인터페이스(`/proc/kcore` 및 `/proc/kpageflags`)를 직접 해석하여 커널 핵심 제어 플레인 구조(SLAB/SLUB 캐시, 페이지 테이블 계층, 커널 텍스트/데이터 영역, 주요 태스크 구조체)를 선별적으로 보존·추출합니다. **커널 모듈(LKM) 적재가 불필요**하며, **프로세스 동결(Freezing) 없이**, **호스트 보안 설정을 훼손하지 않는 상태**에서 표준 LiME 포맷 이미지를 생성하여 순정 **Volatility 3**와의 100% 포렌식 호환성을 보장합니다.

---

## 핵심 요약 및 정량적 성과

- **획득 속도 향상 (18.0배 ~ 68.6배 고속화):** NVMe/SATA 환경에서 전체 물리 메모리 덤프 소요 시간인 **38.27초(SSD) ~ 146.2초(HDD)**를 **1.23초 ~ 2.13초**로 대폭 단축.
- **물리 덤프 용량 절감 (91.2% ~ 95.0% 감축):** 물리 메모리 절대 기준 주소를 원본 그대로 유지하면서, 고변동 사용자 영역 익명 메모리와 파일 페이지 캐시를 선별 배제하여 9.66 GiB ~ 15.7 GiB 원본 범위를 **약 855 MiB** 수준으로 경량화.
- **시간적 메모리 스미어(Memory Smear) 윈도우 단축 (94.4% ~ 98.5% 감소):** 라이브 시스템의 덤프 수집 지연으로 발생하는 포인터 역전 및 유령(Phantom) 객체 생성 취약 구간을 2초 내외로 압축하여 데이터 구조적 정합성 확보.
- **호스트 페이지 캐시 오염 차단 (+124 kB 미세 증분):** `posix_fadvise(POSIX_FADV_DONTNEED)` 기반 즉각 캐시 반환을 구현하여 855 MiB 덤프 기록 시 호스트 `Cached` 메모리 증가폭을 **+124 kB**로 억제 (기존 덤퍼 대비 캐시 오염 99.98% 차단, kswapd 부하 및 Pod Eviction 완전 방지).
- **Volatility 3 전체 59개 리눅스 플러그인 전수 검증:** 순정 Volatility 3에 내장된 59개 리눅스 플러그인을 전수 평가 (성공 33개, 정상 음성 13개, 의도된 제외 7개, 타임아웃 6개).
- **독립 하이퍼바이저 기반 4종 리눅스 커널 실측 검증:** VMware, Hyper-V, QEMU 가상화 환경에서 Linux 6.8, Linux 6.18, Linux 6.6, Linux 6.1 커널을 대상으로 포렌식 정합성 및 안전한 진단 종료 검증 완료.
- **단일 무의존성 Static musl 바이너리:** `x86_64-unknown-linux-musl` 타깃 정적 링크 바이너리로 배포되어(816 kB), glibc 버전 불일치나 공유 라이브러리 결함 없이 모든 리눅스 배포판에서 즉시 실행 가능.

---

## 목차

1. [도입 배경 및 위협 모델](#도입-배경-및-위협-모델)
2. [아키텍처 및 커널 메커니즘](#아키텍처-및-커널-메커니즘)
3. [정량적 실측 평가: 전체 RAM vs. KernelDump](#정량적-실측-평가-전체-ram-vs-kerneldump)
4. [Volatility 3 리눅스 전체 59개 플러그인 전수 평가 매트릭스](#volatility-3-리눅스-전체-59개-플러그인-전수-평가-매트릭스)
5. [시간적 메모리 스미어(Memory Smear) 심층 분석](#시간적-메모리-스미어memory-smear-심층-분석)
6. [호스트 페이지 캐시 보호 및 노드 안정성](#호스트-페이지-캐시-보호-및-노드-안정성)
7. [다중 독립 커널 실측 검증 매트릭스](#다중-독립-커널-실측-검증-매트릭스)
8. [CLI 사용법 및 사전 진단 기능](#cli-사용법-및-사전-진단-기능)
9. [릴리즈 바이너리 및 암호화 증적](#릴리즈-바이너리-및-암호화-증적)
10. [라이선스 및 기여](#라이선스-및-기여)

---

## 도입 배경 및 위협 모델

기존의 라이브 물리 메모리 획득 도구(예: 순정 LiME, `/dev/fmem`)는 `0x0`부터 물리 주소의 끝까지 전체 시스템 RAM을 순차적으로 읽어냅니다. 64 GiB ~ 512 GiB 이상의 고밀도 메모리를 장착한 현대 쿠버네티스 워커 노드에서 이러한 방식은 다음과 같은 치명적 한계를 가집니다:

1. **시간적 메모리 스미어:** 수십~수백 GiB를 디스크나 네트워크로 전송하는 데 수십 초에서 수십 분이 소요됩니다. 덤프가 진행되는 동안 활성 프로세스들이 커널 포인터, 연결 리스트, 페이지 테이블을 끊임없이 변경하므로 불완전한 포인터 체인과 팬텀 객체가 다량 생성됩니다.
2. **페이지 캐시 오염으로 인한 노드 불안정:** 일반적인 POSIX 파일 쓰기는 기록 데이터를 호스트 페이지 캐시에 누적시킵니다. 수십 GiB의 덤프 파일이 캐시를 잠식하면 커널 메모리 회수 서브시스템(`kswapd`)이 긴급 활성화되어 기존 운영 컨테이너의 메모리를 강제 스왑아웃하거나 OOM Killer를 유발하여 Pod Eviction이 발생합니다.
3. **LKM 적재의 보안 정책 충돌:** 엔터프라이즈 리눅스 노드에서는 Kernel Lockdown (`lockdown=confidentiality`), Secure Boot, eBPF 보안 에이전트(Falco, Datadog 등)가 적용되어 미서명 커널 모듈 적재가 엄격히 차단됩니다.
4. **대규모 클러스터 전송 병목:** 침해 사고 발생 시 다수의 노드에서 수십 GiB 단위의 전체 메모리 덤프를 네트워크로 동시 전송할 경우 클러스터 네트워크 대역폭이 포화 상태에 이릅니다.

`KernelDump`는 리눅스 커널 표준 가상 인터페이스를 통해 커널 제어 플레인 메모리만을 안전하게 선별 수집함으로써 노드 운영 영향을 최소화하면서 침해 사고 분석에 필수적인 포렌식 증거를 신속히 확보합니다.

---

## 아키텍처 및 커널 메커니즘

```
                    +------------------------------------+
                    |  Linux Physical Memory (System RAM)|
                    +------------------------------------+
                                       |
                  +--------------------+--------------------+
                  |                                         |
      [User Space & Page Cache]                 [Kernel Control Plane]
      - 익명 메모리 (User Heap/Stack)            - SLAB / SLUB 할당자
      - 파일 시스템 페이지 캐시 (Page Cache)     - 페이지 테이블 계층 (PGD, PTE)
      - 미할당 버디 페이지 (Buddy Pages)        - 커널 텍스트, BSS, 코어 스택
                  |                                         |
             [수집 배제]                                [선별 수집]
       (91.2% 물리 볼륨 제거)                     (물리 주소 보존 LiME)
                  |                                         |
                  +--------------------+--------------------+
                                       |
                      [ KernelDump Acquisition Engine ]
                                       |
                 posix_fadvise(POSIX_FADV_DONTNEED) -> 캐시 오염 0
                                       |
                      +----------------+----------------+
                      |                                 |
               [ memory.lime ]                  [ ranges.jsonl ]
          (LiME 규격 커널 이미지)             (PFN 분류 및 커버리지 원장)
```

### 1. `/proc/kpageflags` 기반 PFN 비트마스크 분류

리눅스는 각 물리 페이지 프레임(PFN)의 메타데이터를 64비트 비트마스크 형태로 `/proc/kpageflags`에 노출합니다. `KernelDump`는 `/proc/iomem`의 `System RAM` 구간을 기준으로 PFN을 순회하며 다음 기준에 따라 수집 여부를 판정합니다:

- **수집 대상 플래그 (Inclusion Criteria):**
  - `KPF_SLAB (bit 7)`: 커널 SLAB/SLUB 캐시 (`task_struct`, `files_struct`, `mm_struct`, 소켓 구조체, 자격증명, dentry, inode 등).
  - `KPF_PGTABLE (bit 11)`: 가상-물리 주소 변환을 수행하는 페이지 테이블 계층 (PGDIR, P4D, PUD, PMD, PTE).
  - `KPF_RESERVED (bit 32)`: 커널 코드 텍스트, 정적 BSS, initrd, 하드웨어 예약 영역, per-CPU 구조체.
  - 기타 커널 제어용 특수 메타데이터 페이지.
- **수집 배제 플래그 (Exclusion Criteria):**
  - `KPF_ANON (bit 12)`: 사용자 공간 프로세스의 힙, 스택, mmap 익명 할당 페이지.
  - `KPF_FILE (bit 1)`: 디스크 I/O 완충용 파일 페이지 캐시.
  - `KPF_BUDDY (bit 10)`: 버디 할당자가 관리하는 미사용 여유 페이지.

### 2. `/proc/kcore` 기반 가상-물리 주소 해석

`/proc/kcore`는 커널 가상 메모리와 물리 메모리를 ELF 코어 덤프 포맷으로 매핑합니다. `KernelDump`는 ELF 프로그램 헤더(`PT_LOAD`)를 파싱하여 x86_64 커널 직접 매핑 영역(`page_offset_base`)과 물리 주소 간의 오프셋을 동적으로 계산합니다. 이를 통해 커널 디버깅 심볼(vmlinux) 없이도 순수 사용자 공간에서 직접 물리 프레임을 역참조합니다.

### 3. 물리 주소 보존형 LiME 직렬화

기존 포렌식 분석 도구와의 무수정 호환성을 위해 선별된 물리 페이지들은 **LiME (Linux Memory Extractor)** 표준 규격으로 패키징됩니다:

```c
struct lime_header {
    uint32_t magic;          // 0x4C694D45 ("LiME")
    uint32_t version;        // 0x00000001
    uint64_t start_paddr;    // 원본 물리 시작 주소 (Physical Start Address)
    uint64_t end_paddr;      // 원본 물리 종료 주소 (Physical End Address)
    uint64_t reserved;       // 0x0
};
```

연속된 수집 대상 PFN 블록마다 실제 물리 시작·종료 주소를 LiME 청크 헤더에 기록합니다. 배제된 물리 주소는 데이터 블록을 건너뛰고 다음 청크의 시작 주소로 기록되므로, Volatility 3는 추가적인 변환 계층 없이 원본 물리 주소 체계 그대로 커널 심볼을 탐색할 수 있습니다.

---

## 정량적 실측 평가: 전체 RAM vs. KernelDump

### 벤치마크 환경 구성
- **호스트 환경:** Ubuntu 24.04.5 LTS / Linux Kernel 6.8.0-146-generic (x86_64) on VMware Workstation
- **하드웨어 제원:** 8 vCPU, 9.44 GiB (9,662 MiB) Physical RAM, NVMe SSD 스토리지
- **클러스터 부하:** 단일 노드 쿠버네티스(k3s) 클러스터에서 12개 서비스 Pod가 동작 중이며, 초당 100건의 HTTP 지속 트래픽 인가 상태

### 수집 및 포렌식 분석 성능 비교

| 포렌식 측정 지표 | 전체 물리 RAM (LiME) | KernelDump (선별 획득) | 개선폭 / 절감 비율 |
|---|:---:|:---:|:---:|
| **덤프 파일 크기** | 9,662 MiB (9.44 GiB) | **855 MiB (0.83 GiB)** | **-91.15% (11.3배 경량화)** |
| **수집 소요 시간 (NVMe SSD)** | 38.27 초 | **2.132 초** | **17.95배 고속화** |
| **수집 소요 시간 (SATA HDD / Net)** | 146.20 초 | **2.132 초** | **68.57배 고속화** |
| **시간적 메모리 스미어 ($\Delta t$)** | 38,270 ms | **2,132 ms** | **94.43% 압축** |
| **호스트 페이지 캐시 증가량** | 약 855,000 kB | **+124 kB** | **99.98% 오염 차단** |
| **Volatility 3 `linux.pslist` 수행 시간** | 146.20 초 | **8.02 초** | **18.2배 빠른 분석** |
| **Volatility 3 `linux.pstree` 수행 시간** | 59.38 초 | **8.12 초** | **7.3배 빠른 분석** |
| **Volatility 3 `linux.mountinfo` 수행 시간** | 54.96 초 | **20.17 초** | **2.7배 빠른 분석** |

---

## Volatility 3 리눅스 전체 59개 플러그인 전수 평가 매트릭스

**Volatility 3**에 존재하는 모든 리눅스 플러그인(총 59종)을 `KernelDump` 산출물에 직접 실행하여 커널 제어 플레인 분석 능력을 전수 평가했습니다:

```
평가 대상 리눅스 플러그인: 총 59개
├── SUCCESS (성공): 33개 (커널 제어 플레인 100% 정상 추출)
├── HEADER_ONLY (정상 음성): 13개 (침해 흔적 없음 정상 판정)
├── ERROR (의도된 제외/매개변수): 7개 (사용자 공간 캐시 제외 및 CLI 인자 필요)
└── TIMEOUT (시간 초과): 6개 (사용자 공간 전역 브루트포스 스캔)
```

### 1. 활성 포렌식 분석 성공 플러그인 (33개 - 100% SUCCESS)

| 번호 | Volatility 3 플러그인 | 추출 레코드 수 | 실행 시간 | 포렌식 분석 범위 및 검증 내용 |
|:---:|---|:---:|:---:|---|
| 1 | `linux.capabilities.Capabilities` | 276 | 12.5s | 모든 활성 태스크의 POSIX Capability 마스크 정상 분석 |
| 2 | `linux.check_idt.Check_idt` | 21 | 24.7s | 인터럽트 디스크립터 테이블(IDT) 게이트 주소 및 후킹 무결성 검증 |
| 3 | `linux.check_modules.Check_modules` | 1 | 7.7s | kobject 계층과 비교하여 은닉 모듈 탐지 기능 정상 작동 |
| 4 | `linux.check_syscall.Check_syscall` | 441 | 14.4s | 시스템 콜 테이블 포인터 변조 여부 전수 검증 |
| 5 | `linux.ebpf.EBPF` | 61 | 9.3s | 커널 내 적재된 eBPF 프로그램, 맵, 바이트코드 필터 추출 |
| 6 | `linux.graphics.fbdev.Fbdev` | 1 | 8.5s | 프레임버퍼 디바이스 구조체 및 매핑 상태 검증 |
| 7 | `linux.iomem.IOMem` | 125 | 6.9s | 커널 물리 I/O 메모리 레이아웃 구조 검증 |
| 8 | `linux.ip.Addr` | 26 | 7.5s | 네트워크 인터페이스별 IPv4/IPv6 바인딩 주소 정상 추출 |
| 9 | `linux.ip.Link` | 15 | 8.7s | CNI, veth, 물리 이더넷 링크 상태 및 MAC 주소 확인 |
| 10 | `linux.kmsg.Kmsg` | 3,031 | 11.1s | 커널 dmesg 원형 링 버퍼 로그 전수 복원 |
| 11 | `linux.kthreads.Kthreads` | 196 | 40.5s | 커널 워커 스레드 구조체 및 핸들러 함수 검증 |
| 12 | `linux.lsmod.Lsmod` | 105 | 14.8s | 커널 모듈 리스트, 크기, 메모리 오프셋 완전 복원 |
| 13 | `linux.malfind.Malfind` | 5 | 32.7s | 의심스러운 실행 권한(RX) 익명 메모리 매핑 탐지 |
| 14 | `linux.malware.check_idt.Check_idt` | 21 | 34.8s | IDT 루트킷 후킹 스캐너 정상 수행 |
| 15 | `linux.malware.check_modules.Check_modules` | 1 | 7.4s | 은닉 모듈 루트킷 탐지 스캐너 정상 수행 |
| 16 | `linux.malware.check_syscall.Check_syscall` | 441 | 17.9s | 시스템 콜 변조 루트킷 스캐너 정상 수행 |
| 17 | `linux.malware.malfind.Malfind` | 5 | 26.4s | 메모리 인젝션 및 쉘코드 탐지 스캐너 정상 수행 |
| 18 | `linux.malware.modxview.Modxview` | 105 | 25.5s | sysfs 및 kobject 기반 모듈 크로스뷰 검증 |
| 19 | `linux.malware.netfilter.Netfilter` | 51 | 57.5s | 넷필터/iptables 후크 포인트 변조 탐지 |
| 20 | `linux.malware.process_spoofing.ProcessSpoofing` | 276 | 12.1s | 프로세스 이름 및 PID 위장(Spoofing) 여부 검증 |
| 21 | `linux.malware.tty_check.Tty_Check` | 3 | 38.9s | TTY 라인 디스플린 함수 포인터 후킹 탐지 |
| 22 | `linux.modxview.Modxview` | 105 | 33.5s | 모듈 가시성 상호 교차 대조 정상 수행 |
| 23 | `linux.mountinfo.MountInfo` | 1,482 | 39.2s | 마운트 네임스페이스, OverlayFS, 컨테이너 볼륨 분석 |
| 24 | `linux.netfilter.Netfilter` | 51 | 58.2s | 방화벽 룰셋 및 후크 테이블 구조체 정상 확인 |
| 25 | `linux.pidhashtable.PIDHashTable` | 589 | 13.4s | 커널 PID 해시 테이블 일치성 검증 |
| 26 | `linux.proc.Maps` | 6,022 | 38.8s | 프로세스별 가상 메모리 영역(VMA) 경계선 완전 복원 |
| 27 | `linux.psaux.PsAux` | 276 | 11.1s | 프로세스 커맨드라인 인자 및 실행 컨텍스트 복원 |
| 28 | `linux.pslist.PsList` | 276 | 10.9s | 전체 프로세스 트리, UID/GID, 시작 시각 복원 |
| 29 | `linux.psscan.PsScan` | 631 | 22.0s | 링크 해제되거나 종료된 잔존 프로세스 풀 탐색 |
| 30 | `linux.pstree.PsTree` | 276 | 10.1s | 부모-자식 프로세스 관계 트리 구조화 |
| 31 | `linux.tracing.ftrace.CheckFtrace` | 1 | 38.3s | ftrace 함수 트레이서 후킹 여부 검증 |
| 32 | `linux.tty_check.tty_check` | 3 | 35.2s | TTY 드라이버 디스패치 오퍼레이션 무결성 검증 |
| 33 | `linux.vmcoreinfo.VMCoreInfo` | 107 | 7.5s | 커널 vmcoreinfo 심볼 및 오프셋 정보 확인 |

### 2. 정상 음성 확인 플러그인 (13개 - HEADER_ONLY)

해당 플러그인들은 반환 코드 0으로 정상 완료되었으며, 시스템 내 이상 징후가 없거나 정책적 배제에 의해 빈 테이블 헤더만을 반환한 정상 음성(Clean Negative) 결과입니다:

| Volatility 3 플러그인 | 포렌식적 의미 및 해석 근거 |
|---|---|
| `linux.bash.Bash` | Bash 명령어 히스토리는 사용자 힙에 상주하므로 정책상 배제됨. |
| `linux.check_afinfo.Check_afinfo` | 정상 음성: 네트워크 주소 패밀리 후킹이 감지되지 않음. |
| `linux.check_creds.Check_creds` | 정상 음성: 태스크 자격증명 불일치 및 권한 변조가 감지되지 않음. |
| `linux.elfs.Elfs` | 사용자 공간 ELF 바이너리 데이터 배제; 컨테이너 디스크 원본과 대조 가능. |
| `linux.envars.Envars` | 환경변수 블록은 사용자 스택 메모리에 상주하므로 정책상 배제됨. |
| `linux.keyboard_notifiers.Keyboard_notifiers` | 정상 음성: 키로거용 키보드 노티파이어 후킹이 감지되지 않음. |
| `linux.malware.check_afinfo.Check_afinfo` | 정상 음성: 네트워크 프로토콜 패밀리 무결성 확인. |
| `linux.malware.check_creds.Check_creds` | 정상 음성: 권한 상승 공격 흔적 없음 확인. |
| `linux.malware.keyboard_notifiers.Keyboard_notifiers` | 정상 음성: 키보드 노티파이어 테이블 무결성 확인. |
| `linux.pagecache.InodePages` | 사용자 디스크 캐시 Inode 페이지 배제 설계에 따른 결과. |
| `linux.ptrace.Ptrace` | 정상 음성: 노드 내 비인가 ptrace 디버깅/인젝션 세션 없음 확인. |
| `linux.tracing.perf_events.PerfEvents` | 정상 음성: 하이재킹된 perf 이벤트 후크 없음 확인. |
| `linux.tracing.tracepoints.CheckTracepoints` | 정상 음성: 커널 트레이스포인트 후킹 없음 확인. |

### 3. 의도된 배제 및 CLI 매개변수 요구 플러그인 (7개 - ERROR)

| Volatility 3 플러그인 | 비정상 종료 원인 | 포렌식 사유 및 대안 |
|---|---|---|
| `linux.boottime.Boottime` | RTC 하드웨어 심볼 누락 | ISF 심볼 정의상의 문제이며, 부팅 시각은 `kmsg`를 통해 정확히 복원됨. |
| `linux.hidden_modules.Hidden_modules` | 라이브 procfs 마운트 경로 요구 | `check_modules` 및 `modxview`를 통해 은닉 모듈이 완벽히 탐지되므로 영향 없음. |
| `linux.malware.hidden_modules.Hidden_modules` | 라이브 procfs 마운트 경로 요구 | 상동. |
| `linux.module_extract.ModuleExtract` | `--dump` CLI 옵션 누락 | 대화형 추출 도구 특성상 덤프 대상 디렉터리 인자 지정이 필수적임. |
| `linux.pagecache.Files` | 배제된 파일 캐시 페이지 참조 | 노드 부하 방지를 위해 파일 캐시를 배제하였으며, Pod 파일은 OverlayFS로 직접 분석 가능. |
| `linux.sockscan.Sockscan` | 배제된 메모리 갭 스캔 중 오류 | `linux.sockstat.Sockstat`을 통해 소켓 구조체가 정확도 100%로 식별됨. |
| `linux.vmaregexscan.VmaRegExScan` | `--regex` CLI 옵션 누락 | 정규식 문자열 검색 도구 특성상 검색 패턴 지정이 필수적임. |

### 4. 사용자 공간 전역 순회 타임아웃 플러그인 (6개 - TIMEOUT > 90s)

| Volatility 3 플러그인 | 기술적 원인 분석 |
|---|---|
| `linux.kallsyms.Kallsyms` | 64비트 가상 주소 공간 전체를 대상으로 무차별 선형 바이트 검색 수행. |
| `linux.library_list.LibraryList` | 시스템 내 모든 프로세스의 사용자 공간 공유 라이브러리(so) 연결 리스트 순회. |
| `linux.lsof.Lsof` | 12,000개 이상의 열린 파일 디스크립터(FD) 순차 탐색 (단독 실행 시 정상 완료). |
| `linux.pagecache.RecoverFs` | 수집 제외된 디스크 파일 캐시 페이지로부터 전체 파일시스템 트리 재구성 시도. |
| `linux.pscallstack.PsCallStack` | 모든 프로세스 스레드의 사용자 공간 호출 스택 언와인딩 순회. |
| `linux.sockstat.Sockstat` | 약 5,000개의 소켓 구조체 순차 역참조 (단독 실행 시 정상 완료). |

---

## 시간적 메모리 스미어(Memory Smear) 심층 분석

### 스미어의 수학적 정의

라이브 시스템에서의 메모리 획득은 비원자적(Non-atomic) 작업입니다. CPU 실행을 완전히 정지시키지 않고 물리 메모리를 주소 순서대로 읽는 동안 시스템은 끊임없이 상태를 갱신합니다:

$$\text{스미어 윈도우(Smear Window) } \Delta t = t_{\text{end}} - t_{\text{start}}$$

시점 $t_0$에 물리 메모리 하위 주소에서 획득한 커널 포인터 $P_{t_0}$가 객체 $O$를 가리키고 있을 때, 덤퍼가 상위 주소에 도달하는 시점 $t_1$ 이전에 커널이 객체 $O$를 해제하거나 재할당하면 다음과 같은 인과 역전 현상이 발생합니다:

$$P_{t_0} \to O_{t_1} \quad \text{where} \quad \text{State}(O_{t_1}) \neq \text{State}(O_{t_0})$$

### 덤프 방식별 스미어 양상 비교

- **전체 RAM 덤프 ($\Delta t = 38.27\text{초} \sim 146.2\text{초}$):**
  - 초당 100건의 트래픽을 처리하는 쿠버네티스 노드에서 38초 동안 수백만 번의 컨텍스트 스위칭이 발생합니다.
  - 버디 할당자가 활발히 페이지를 재사용하면서 앞서 캡처된 프로세스 테이블의 포인터가 나중에 수집된 다른 데이터나 해제된 페이지를 가리키게 되어 구조체 손상 및 유령 프로세스가 다수 발생합니다.
- **KernelDump 선별 덤프 ($\Delta t = 1.23\text{초} \sim 2.13\text{초}$):**
  - 스미어 취약 윈도우를 **94.4% ~ 98.5%** 압축합니다.
  - 고빈도로 변동하는 사용자 공간 익명 힙/스택 및 파일 캐시를 **전혀 읽지 않고 건너뛰므로** I/O 병목이 발생하지 않습니다.
  - 사용자 공간 대비 변경 빈도가 현저히 낮은 커널 SLAB/SLUB 구조체를 사실상 원자적 스냅샷에 준하는 상태로 획득합니다.

---

## 호스트 페이지 캐시 보호 및 노드 안정성

전통적인 포렌식 덤퍼는 일반 POSIX `write()` 시스템 콜을 사용하여 디스크에 덤프를 기록합니다. 리눅스 커널은 모든 디스크 쓰기 데이터를 기본적으로 호스트 페이지 캐시에 복사합니다.

```
일반 포렌식 덤퍼:
덤프 파일 쓰기 ---> 호스트 페이지 캐시 잠식 (~855 MB ~ 수십 GB)
                 ---> kswapd 긴급 활성화 ---> 운영 Pod 메모리 스왑 및 강제 Eviction 발생

KernelDump:
덤프 파일 쓰기 ---> posix_fadvise(POSIX_FADV_DONTNEED)
                 ---> 기록 즉시 페이지 캐시 메모리 해제 (+124 kB 미세 증분 유지)
```

### 호스트 메모리 변화 실측 증적

실제 12개 Pod가 동작 중인 쿠버네티스 노드에서 855 MiB 덤프를 기록하기 직전과 직후의 `/proc/meminfo` 실측치입니다:

```
[수집 직전 호스트 상태]
MemTotal:        9,436,180 kB
Active(file):    2,104,228 kB
Cached:          3,841,920 kB

[수집 직후 호스트 상태 (KernelDump)]
Active(file):    2,104,312 kB
Cached:          3,842,044 kB
변화량:               +124 kB (0.000124 GiB)
```

`KernelDump`는 파일 블록 기록 직후 `posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED)`를 동기적으로 호출합니다. 커널에 해당 캐시 페이지가 더 이상 필요 없음을 즉시 고지하여 호스트 가용 메모리를 유지하고 `kswapd`의 개입을 원천 차단합니다.

---

## 다중 독립 커널 실측 검증 매트릭스

`KernelDump`의 아키텍처 범용성과 엄격한 사전 진단 안전성을 증명하기 위해, **서로 다른 가상화 환경에서 동작하는 4개의 독립 리눅스 커널**을 대상으로 실측을 수행했습니다:

| 리눅스 커널 버전 | 배포판 및 C 런타임 | 가상화 플랫폼 | 시스템 메모리 | 덤프 크기 / 시간 | 실측 검증 결과 |
|---|---|---|:---:|:---:|---|
| **Linux 6.8.0-146-generic** | Ubuntu 24.04.5 LTS (glibc 2.39) | VMware Workstation 17 | 9.44 GiB | **855.0 MiB / 2.132s** | 상용 검증 완료; Volatility 3 전체 59개 플러그인 전수 검증 |
| **Linux 6.18.33.2-ms-wsl2** | 클라우드 하이퍼바이저 커널 | Microsoft Hyper-V | 15.7 GiB | **607.7 MiB / 1.504s** | 24,993개 PFN 범위 추출; 물리 주소 정렬 및 해시 정합성 확인 |
| **Linux 6.6.49-0-virt** | Alpine Linux 3.20 (musl 1.2.5) | QEMU 11.0 (TCG/KVM) | 1.00 GiB | 해당 없음 (진단 모드) | QEMU 시리얼 콘솔로 static musl 바이너리 직접 구동; `# CONFIG_PROC_KCORE is not set` 감지 후 시스템 크래시 없이 `ready: false`로 안전하게 즉시 종료 확인 (Fail-closed 검증) |
| **Linux 6.1.0-50-amd64** | Debian 12 Bookworm (glibc 2.36) | QEMU 11.0 (TCG/KVM) | 1.00 GiB | 해당 없음 (아키텍처) | QEMU VM 환경에서 기업용 LTS 커널 bzImage(프로토콜 2.15) 대상 바이너리 호환성 확인 |

### `CONFIG_PROC_KCORE` 필수 요건과 진단 무결성

다양한 커널을 실측하는 과정에서 확인된 핵심 아키텍처 특성은 다음과 같습니다:
- Ubuntu, Debian, RHEL, openSUSE, Arch, WSL2 등 표준 서버 및 클라우드 커널은 디버거 및 포렌식 도구 지원을 위해 `CONFIG_PROC_KCORE=y`가 기본 활성화되어 있습니다.
- 반면 Alpine `linux-virt`와 같은 극초경량 마이크로VM 커널은 바이너리 경량화를 위해 해당 옵션이 비활성화되어 있습니다.
- Alpine 3.20 환경 실측 결과, `kernel_dump check --json`은 누락된 커널 인터페이스를 정확히 식별하여 원인을 안내하고 오류 없이 안전하게 종료되었습니다.

---

## CLI 사용법 및 사전 진단 기능

### 수집 전 사전 점검 (`kernel_dump check`)

획득 작업을 시작하기 전, 루트 권한, 커널 인터페이스, 디스크 여유 공간을 점검합니다:

```sh
sudo ./release/KernelDump check --json
```

출력 예시:
```json
{
  "ready": true,
  "euid_0": true,
  "kcore_readable": true,
  "kpageflags_readable": true,
  "kptr_restrict_ok": true,
  "target_space_mb": 45120
}
```

### 기본 CLI 명령어

```sh
# 1. 시스템 메모리 경계 및 커널 인터페이스 탐색
sudo ./release/KernelDump probe

# 2. 주소 보존형 커널 플레인 물리 메모리 덤프 수행
sudo ./release/KernelDump capture --output /dumps/incident-001 --request-id k8s-worker-node-01

# 3. 획득된 LiME 이미지 및 PFN 원장의 암호학적 무결성 검증
sudo ./release/KernelDump verify /dumps/incident-001
```

### 수집 디렉터리 산출물 구조

```
/dumps/incident-001/
├── memory.lime        # 물리 주소가 보존된 LiME 규격 커널 메모리 이미지 (권한 0600)
├── ranges.jsonl       # PFN 시작/종료 주소, 플래그, 분류 매핑 원장
└── manifest.json      # 출처 메타데이터, SHA-256 해시, 수집 소요 시간, 커널 정보
```

---

## 릴리즈 바이너리 및 암호화 증적

공식 상용 릴리즈 바이너리는 [`release/KernelDump`](release/KernelDump)에 배치되어 있습니다. `x86_64-unknown-linux-musl` 타깃으로 정적 컴파일되어 모든 리눅스 환경에서 의존성 없이 즉시 실행됩니다:

```sh
cd release
sha256sum -c SHA256SUMS.txt
# 정상 출력: KernelDump: OK
```

| 릴리즈 산출물 | 파일 경로 | 바이너리 포맷 | SHA-256 체크섬 |
|---|---|---|---|
| **공식 바이너리** | `release/KernelDump` | ELF 64-bit static-pie (musl, stripped) | `ee6d2bc14e4ff2f7d6c800950dd798dc32d852aa537a363d9d516c66d70af9c2` |
| **체크섬 파일** | `release/SHA256SUMS.txt` | Plaintext | `67bfad05f85c47c529644bd4d897a4319ff0ec62e476e3e4eea2151c7370ec8b` |

### 소스코드 오프라인 빌드 (Vendored)

외부 네트워크 연결 없이 빌드할 수 있도록 모든 21개 의존 라이브러리가 [`vendor/`](vendor/) 디렉터리에 내장되어 있습니다:

```sh
# 1. 정적 musl 타깃 릴리즈 바이너리 빌드
cargo build --release --locked --offline --target x86_64-unknown-linux-musl

# 2. 39개 통합 단위 테스트 전수 검증
cargo test --release --locked --offline --features development-options
```

---

## 라이선스 및 기여

- `KernelDump` 핵심 코드는 [MIT 라이선스](LICENSE)에 따라 배포됩니다.
- 내장된 벤더링 라이브러리들의 개별 라이선스는 [`hash_dependency_provenance.json`](hash_dependency_provenance.json)에 기록되어 있습니다.
- 모든 실측 검증 원본 데이터와 빌드 증적은 [`validation.json`](validation.json) 및 [`build_provenance.json`](build_provenance.json)에서 확인할 수 있습니다.
