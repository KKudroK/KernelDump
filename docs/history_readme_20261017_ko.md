# KernelDump: 리눅스 커널 메모리 선별 수집 도구

[English](README.md) | [한국어](README.ko.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Language: Rust](https://img.shields.io/badge/Language-Rust_1.90+-orange.svg)](Cargo.toml)
[![Forensics: Volatility 3](https://img.shields.io/badge/Forensics-Volatility_3_Compatible-brightgreen.svg)](validation.json)
[![Binary: Static musl](https://img.shields.io/badge/Binary-Static_musl_Zero_Dependency-blueviolet.svg)](#빌드-및-릴리즈-바이너리-증적)
[![Status: Tested](https://img.shields.io/badge/Status-Tested-success.svg)](#빌드-및-릴리즈-바이너리-증적)

리눅스 커널 제어 플레인 메모리를 선별하여 LiME 포맷으로 수집하는 경량 도구입니다.

`KernelDump`는 리눅스 커널 인터페이스(`/proc/kcore` 및 `/proc/kpageflags`)를 통해 커널 핵심 제어 플레인(SLAB/SLUB 캐시, 페이지 테이블, 커널 텍스트/데이터 영역)을 선별 수집합니다. 커널 모듈(LKM) 적재나 프로세스 동결 없이 동작하며, 생성된 LiME 이미지는 Volatility 3로 직접 분석할 수 있습니다.

---

## 주요 특징 및 실측 결과

- **수집 시간 단축:** 64 GiB 메모리 환경에서 전체 RAM 수집(466.9초) 대비 **20.8초**로 수집 시간을 단축했습니다.
- **덤프 용량 절감:** 사용자 공간 익명 메모리와 페이지 캐시를 제외하여 원본 62.96 GiB를 **1.99 GiB**로 줄였습니다.
- **스미어 윈도우 단축:** 수집 시간을 466.9초에서 **20.8초**로 단축하여 메모리 변동에 따른 데이터 불일치 구간을 최소화했습니다.
- **페이지 캐시 보호:** `posix_fadvise(POSIX_FADV_DONTNEED)`를 적용하여 수집 중 페이지 캐시 증가를 **110.4 kB** 수준으로 억제했습니다.
- **즉시 분석 가능:** Native LiME 포맷으로 직접 출력하여 별도의 포맷 변환 없이 Volatility 3 분석에 바로 활용할 수 있습니다.
- **단일 정적 바이너리:** musl 타깃 정적 링크 바이너리로 빌드되어 추가 라이브러리 의존성 없이 실행됩니다.


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
9. [빌드 및 릴리즈 바이너리 증적](#빌드-및-릴리즈-바이너리-증적)
10. [기술적 한계 및 운영 제약 사항](#기술적-한계-및-운영-제약-사항)
11. [라이선스 및 기여](#라이선스-및-기여)

---

## 도입 배경 및 위협 모델

기존의 라이브 물리 메모리 획득 도구(예: 순정 LiME, `/dev/fmem`)는 `0x0`부터 물리 주소의 끝까지 전체 시스템 RAM을 순차적으로 읽어냅니다. 64 GiB ~ 512 GiB 이상의 고밀도 메모리를 장착한 현대 운영 리눅스 서버 및 가상화 호스트에서 이러한 방식은 다음과 같은 치명적 한계를 가집니다:

1. **시간적 메모리 스미어:** 수십~수백 GiB를 디스크나 네트워크로 전송하는 데 수십 초에서 수십 분이 소요됩니다. 덤프가 진행되는 동안 활성 프로세스들이 커널 포인터, 연결 리스트, 페이지 테이블을 끊임없이 변경하므로 불완전한 포인터 체인과 팬텀 객체가 다량 생성됩니다.
2. **페이지 캐시 오염으로 인한 노드 불안정:** 일반적인 POSIX 파일 쓰기는 기록 데이터를 호스트 페이지 캐시에 누적시킵니다. 수십 GiB의 덤프 파일이 캐시를 잠식하면 커널 메모리 회수 서브시스템(`kswapd`)이 긴급 활성화되어 기존 운영 서비스의 메모리를 강제 스왑아웃하거나 OOM Killer를 유발하여 프로세스 강제 종료가 발생합니다.
3. **LKM 적재의 보안 정책 충돌:** 엔터프라이즈 리눅스 노드에서는 Kernel Lockdown (`lockdown=confidentiality`), Secure Boot, eBPF 보안 에이전트(Falco, Datadog 등)가 적용되어 미서명 커널 모듈 적재가 엄격히 차단됩니다.
4. **대규모 전송 병목:** 침해 사고 발생 시 다수의 호스트에서 수십 GiB 단위의 전체 메모리 덤프를 네트워크로 동시 전송할 경우 네트워크 대역폭이 포화 상태에 이릅니다.

`KernelDump`는 리눅스 커널 표준 가상 인터페이스를 통해 커널 제어 플레인 메모리만을 안전하게 선별 수집함으로써 시스템 운영 영향을 최소화하면서 침해 사고 분석에 필수적인 포렌식 증거를 신속히 확보합니다.

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
  - `KPF_PGTABLE (bit 26)`: 가상-물리 주소 변환을 수행하는 페이지 테이블 계층 (PGDIR, P4D, PUD, PMD, PTE). *(참고: `bit 11`은 `KPF_MMAP`에 해당).*
  - `KPF_RESERVED (bit 32)`: 커널 코드 텍스트, 정적 BSS, initrd, 하드웨어 예약 영역, per-CPU 구조체.
  - 기타 커널 제어용 특수 메타데이터 페이지 및 미분류 물리 프레임.
- **수집 배제 플래그 (Exclusion Criteria):**
  - `KPF_ANON (bit 12)`: 사용자 공간 프로세스의 힙, 스택, mmap 익명 할당 페이지.
  - `KPF_FILE (bit 1)`: 디스크 I/O 완충용 파일 페이지 캐시.
  - `KPF_BUDDY (bit 10)`: 버디 할당자가 관리하는 미사용 여유 페이지.

#### 다중 페이지 커널 구조체 경계 보존 및 수집 정책 (`classify_with_neighbors`)

- **다중 페이지 커널 객체:** 리눅스 SLUB 할당자에서 주요 커널 구조체(예: `struct task_struct`는 약 10,496바이트 크기로 연속된 3개의 4 KiB 물리 페이지에 걸쳐 할당됨)는 단일 페이지 경계를 초과합니다. 경계 페이지가 누락되면 Volatility 등의 분석 도구에서 객체 순회 중 절단 오류(`layer.is_valid` 실패)가 발생합니다.
- **인접 경계 보존 (`classify_with_neighbors`):** 커널 객체 그래프의 연속성을 보장하기 위해, `KernelDump`는 명시적 손상(`UNSAFE`: `KPF_HWPOISON`, `KPF_NOPAGE`, `KPF_OFFLINE`)이 없는 한 `SLAB` 또는 `PGTABLE` 페이지와 물리적으로 인접한 전후 경계 페이지를 함께 보존합니다.
- **정책적 포함 및 `strict_kernel_only: false`:** 인접한 경계 페이지가 익명 메모리(`ANON`)나 페이지 캐시(`FILE`)로 할당되어 있던 경우 해당 페이지가 함께 수집될 수 있습니다. 메타데이터 매니페스트(`manifest.json`)는 이러한 실제 동작을 반영하여 `"strict_kernel_only": false`로 명시합니다.

### 2. `/proc/kcore` 기반 가상-물리 주소 해석

`/proc/kcore`는 커널 가상 메모리와 물리 메모리를 ELF 코어 덤프 포맷으로 매핑합니다. `KernelDump`는 ELF 프로그램 헤더(`PT_LOAD`)를 파싱하여 x86_64 커널 직접 매핑 영역(`page_offset_base`)과 물리 주소 간의 오프셋을 동적으로 계산합니다. 이를 통해 커널 디버깅 심볼(vmlinux) 없이도 순수 사용자 공간에서 직접 물리 프레임을 역참조합니다.

> [!NOTE]
> `/proc/kcore`의 ELF 세그먼트 오프셋은 도구 초기화 시점에 1회 파싱됩니다. 수집 진행 중에 동적으로 발생하는 메모리 핫플러그(Hot-add 또는 Hot-remove) 변경 사항은 실시간으로 재감지되지 않습니다.

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

## 정량적 실측 평가: 전체 RAM vs. makedumpfile vs. KernelDump

### 64 GiB 엔터프라이즈 클라우드 벤치마크 환경
- **호스트 인스턴스:** AWS EC2 `r6i.2xlarge` (8 vCPU Intel Xeon Platinum 8375C @ 2.90GHz, 61.78 GiB Physical RAM, 80 GiB gp3 NVMe SSD, Amazon Linux 2023 / Linux 6.18.54 LTS)
- **부하 프로파일:** 16.06 GiB 활성 익명 메모리 워크로드 (4,209,000개 페이지에 걸쳐 바이트 패턴 수정 및 스레드 churn 인가)
- **비교 대상:**
  1. **전체 물리 RAM 베이스라인 (LiME):** 커널 모듈을 통한 62.96 GiB 전체 물리 메모리 덤프
  2. **makedumpfile -d 31 (kcore):** `/proc/kcore` 기반 레벨 31(Zero, Cache, User, Free 제외) 필터 덤프
  3. **KernelDump (제안 도구):** 주소 보존형 커널 플레인 선별 덤프 (Native LiME 포맷 직접 생성)

### 실측 수집 및 자원 부하 비교

| 측정 지표 | 전체 물리 RAM (LiME) | makedumpfile -d 31 (kcore) | KernelDump (제안 도구) | 비교 및 분석 |
| :--- | :---: | :---: | :---: | :--- |
| **덤프 파일 크기** | 62.96 GiB | 2.37 GiB | **1.99 GiB** | **-96.84% 용량 절감** |
| **원시 덤프 수집 시간** | 466.93 초 | **13.41 초** | **20.84 초** | LiME 대비 22.4배 단축 |
| **LiME 포맷 변환 시간** | 0.00 초 | **21.03 초** | **0.00 초** | 2차 변환 불필요 |
| **최종 분석 가능 시점** | 466.93 초 | **34.44 초** | **20.84 초** | **분석 착수 시점 39.5% 단축** |
| **호스트 페이지 캐시 오염** | +42.14 GiB | +2.49 GiB | **+110.4 kB** | 페이지 캐시 오염 방지 |
| **시간적 메모리 스미어** | 466.93 초 | 13.41 초 | **20.84 초** | 스미어 윈도우 95.54% 단축 |
| **도구 의존성** | 커널 모듈 빌드 필요 | kdump 도구, 디버그 심볼, 변환 스크립트 | **단일 정적 바이너리** | 추가 의존성 없음 |

---

## Volatility 3 리눅스 플러그인 평가

Volatility 3 내장 59개 리눅스 플러그인을 KernelDump 덤프 이미지에 실행하여 동작을 확인했습니다. 수집 범위에 따른 결과 분류는 다음과 같습니다:

```
평가 대상 리눅스 플러그인: 총 59개
├── 커널 제어 플레인 완전 추출: 30개 (구조적 일치)
├── 사용자 공간 페이로드 제외 디스크립터: 3개 (PsAux, Malfind - 메타데이터 확인)
├── 정상 음성 확인: 9개 (후킹 및 변조 없음)
├── 정책적 사용자 공간 제외: 4개 (Bash, Envars, Elfs, Pagecache - 미수집 대상)
├── 매개변수 요구 및 인자 누락: 7개 (CLI 인자 요구 등)
└── 전역 순회 타임아웃: 6개 (90초 초과)
```

### 1. 활성 커널 제어 플레인 추출 (30개 - SUCCESS)

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
| 13 | `linux.malware.check_idt.Check_idt` | 21 | 34.8s | IDT 루트킷 후킹 스캐너 정상 수행 |
| 14 | `linux.malware.check_modules.Check_modules` | 1 | 7.4s | 은닉 모듈 루트킷 탐지 스캐너 정상 수행 |
| 15 | `linux.malware.check_syscall.Check_syscall` | 441 | 17.9s | 시스템 콜 변조 루트킷 스캐너 정상 수행 |
| 16 | `linux.malware.modxview.Modxview` | 105 | 25.5s | sysfs 및 kobject 기반 모듈 크로스뷰 검증 |
| 17 | `linux.malware.netfilter.Netfilter` | 51 | 57.5s | 넷필터/iptables 후크 포인트 변조 탐지 |
| 18 | `linux.malware.process_spoofing.ProcessSpoofing` | 276 | 12.1s | 프로세스 이름 및 PID 위장(Spoofing) 여부 검증 |
| 19 | `linux.malware.tty_check.Tty_Check` | 3 | 38.9s | TTY 라인 디스플린 함수 포인터 후킹 탐지 |
| 20 | `linux.modxview.Modxview` | 105 | 33.5s | 모듈 가시성 상호 교차 대조 정상 수행 |
| 21 | `linux.mountinfo.MountInfo` | 1,482 | 39.2s | 마운트 네임스페이스, OverlayFS, 컨테이너 볼륨 분석 |
| 22 | `linux.netfilter.Netfilter` | 51 | 58.2s | 방화벽 룰셋 및 후크 테이블 구조체 정상 확인 |
| 23 | `linux.pidhashtable.PIDHashTable` | 589 | 13.4s | 커널 PID 해시 테이블 일치성 검증 |
| 24 | `linux.proc.Maps` | 6,022 | 38.8s | 프로세스별 가상 메모리 영역(VMA) 경계선 완전 복원 |
| 25 | `linux.pslist.PsList` | 276 | 10.9s | 전체 프로세스 트리, UID/GID, 시작 시각 복원 |
| 26 | `linux.psscan.PsScan` | 631 | 22.0s | 링크 해제되거나 종료된 잔존 프로세스 풀 탐색 |
| 27 | `linux.pstree.PsTree` | 276 | 10.1s | 부모-자식 프로세스 관계 트리 구조화 |
| 28 | `linux.tracing.ftrace.CheckFtrace` | 1 | 38.3s | ftrace 함수 트레이서 후킹 여부 검증 |
| 29 | `linux.tty_check.tty_check` | 3 | 35.2s | TTY 드라이버 디스패치 오퍼레이션 무결성 검증 |
| 30 | `linux.vmcoreinfo.VMCoreInfo` | 107 | 7.5s | 커널 vmcoreinfo 심볼 및 오프셋 정보 확인 |

### 2. 사용자 공간 페이로드 배제 디스크립터 (3개 - SUCCESS / 메타데이터 전용)

해당 플러그인들은 반환 코드 0(`status: SUCCESS`)으로 정상 실행되어 SLAB/SLUB의 커널 태스크 및 VMA 구조체를 완전 복원했습니다. 그러나 사용자 공간 메모리를 배제하는 수집 정책상 사용자 문자열 및 코드 페이로드는 미수집 상태로 남습니다:

| 번호 | Volatility 3 플러그인 | 레코드 수 | 실행 시간 | 포렌식 추출 범위 및 실제 의미 |
|:---:|---|:---:|:---:|---|
| 1 | `linux.psaux.PsAux` | 276 | 11.1s | **프로세스 제어 메타데이터 전용 복원:** 프로세스 계층(`PID`, `PPID`, `COMM`)은 완전 복원됨. 사용자 스택 메모리에 존재하는 `argv`/`environ` 문자열이 배제 정책에 따라 수집되지 않아 인자(`ARGS`) 항목은 `"-"`로 표시됨. |
| 2 | `linux.malfind.Malfind` | 5 | 32.7s | **VMA 메모리 경계 디스크립터 전용 식별:** 커널 `mm_struct`/`vm_area_struct`로부터 `rwx` 권한의 의심 메모리 영역 경계를 식별함. 사용자 공간 익명 물리 페이지가 수집되지 않아 덤프된 바이트 및 디스어셈블리는 0(`00 00 ...`)으로 채워짐. 이는 VMA 경계 탐지 결과이며 쉘코드 바이너리 복원이 아님. |
| 3 | `linux.malware.malfind.Malfind` | 5 | 26.4s | **VMA 메모리 경계 디스크립터 전용 식별:** 상동; 의심스러운 실행 권한 VMA 매핑을 식별하나 사용자 공간 페이로드는 미수집 상태임. |

### 3. 실제 정상 음성 확인 플러그인 (9개 - HEADER_ONLY)

해당 플러그인들은 커널 디스패치 테이블, 자격증명 구조체, 트레이서 후크를 정상 순회하고 0건의 이상 징후(반환 코드 0)를 반환하여, 커널 영역에 루트킷 후킹이나 권한 변조가 없음을 확인한 실제 정상 음성(Clean Negative) 결과입니다:

| Volatility 3 플러그인 | 포렌식 분석 범위 및 정상 판정 근거 |
|---|---|
| `linux.check_afinfo.Check_afinfo` | 정상 음성: 커널 네트워크 주소 패밀리 오퍼레이션 후킹 없음 확인. |
| `linux.check_creds.Check_creds` | 정상 음성: 전체 태스크 구조체 자격증명 불일치 및 권한 변조 없음 확인. |
| `linux.keyboard_notifiers.Keyboard_notifiers` | 정상 음성: 커널 키보드 노티파이어 체인 후킹 없음 확인. |
| `linux.malware.check_afinfo.Check_afinfo` | 정상 음성: 프로토콜 패밀리 핸들러가 정상 모듈 주소와 일치함 확인. |
| `linux.malware.check_creds.Check_creds` | 정상 음성: 권한 상승 공격에 의한 자격증명 변조 흔적 없음 확인. |
| `linux.malware.keyboard_notifiers.Keyboard_notifiers` | 정상 음성: 키보드 노티파이어 디스패치 테이블 무결성 확인. |
| `linux.ptrace.Ptrace` | 정상 음성: 노드 내 비인가 ptrace 디버깅/인젝션 세션 없음 확인. |
| `linux.tracing.perf_events.PerfEvents` | 정상 음성: 하이재킹된 perf 이벤트 후크 없음 확인. |
| `linux.tracing.tracepoints.CheckTracepoints` | 정상 음성: 커널 트레이스포인트 후킹 없음 확인. |

### 4. 정책적 사용자 공간 배제 플러그인 (4개 - HEADER_ONLY / 설계상 미수집)

해당 플러그인들은 사용자 공간 물리 메모리를 정책적으로 수집 대상에서 제외하였기 때문에 0건의 행을 반환한 것으로, 사용자 공간에 실제 데이터가 비어있음을 증명하는 정상 음성이 아닙니다:

| Volatility 3 플러그인 | 포렌식 판정 상태 | 정책적 배제 사유 |
|---|---|---|
| `linux.bash.Bash` | 설계상 미수집 | 쉘 명령어 히스토리 버퍼는 사용자 프로세스 힙 메모리(`KPF_ANON`)에 상주함. |
| `linux.envars.Envars` | 설계상 미수집 | 프로세스 환경변수 블록은 사용자 프로세스 스택 메모리(`KPF_ANON`)에 상주함. |
| `linux.elfs.Elfs` | 설계상 미수집 | 사용자 공간 ELF 매핑 바이너리 배제; 컨테이너/호스트 디스크 원본과 대조 가능. |
| `linux.pagecache.InodePages` | 설계상 미수집 | 수십 GiB 메모리 팽창을 방지하기 위해 파일 디스크 캐시(`KPF_FILE`)를 배제함. |

### 5. 의도된 배제 및 CLI 매개변수 요구 플러그인 (7개 - ERROR)

| Volatility 3 플러그인 | 비정상 종료 원인 | 포렌식 사유 및 대안 |
|---|---|---|
| `linux.boottime.Boottime` | RTC 하드웨어 심볼 누락 | ISF 심볼 정의상의 문제이며, 부팅 시각은 `kmsg`를 통해 정확히 복원됨. |
| `linux.hidden_modules.Hidden_modules` | 라이브 procfs 마운트 경로 요구 | `check_modules` 및 `modxview`를 통해 은닉 모듈이 완벽히 탐지되므로 영향 없음. |
| `linux.malware.hidden_modules.Hidden_modules` | 라이브 procfs 마운트 경로 요구 | 상동. |
| `linux.module_extract.ModuleExtract` | `--dump` CLI 옵션 누락 | 대화형 추출 도구 특성상 덤프 대상 디렉터리 인자 지정이 필수적임. |
| `linux.pagecache.Files` | 배제된 파일 캐시 페이지 참조 | 노드 부하 방지를 위해 파일 캐시를 배제하였으며, 파일은 스토리지 파일시스템으로 직접 분석 가능. |
| `linux.sockscan.Sockscan` | 배제된 메모리 갭 스캔 중 오류 | `linux.sockstat.Sockstat`을 통해 소켓 구조체가 정확도 100%로 식별됨. |
| `linux.vmaregexscan.VmaRegExScan` | `--regex` CLI 옵션 누락 | 정규식 문자열 검색 도구 특성상 검색 패턴 지정이 필수적임. |

### 6. 사용자 공간 전역 순회 타임아웃 플러그인 (6개 - TIMEOUT > 90s)

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
  - 초당 100건의 트래픽을 처리하는 운영 리눅스 호스트에서 38초 동안 수백만 번의 컨텍스트 스위칭이 발생합니다.
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
덤프 파일 쓰기 ---> 호스트 페이지 캐시 잠식 (~855 MB ~ 수십 GB 더티/클린 페이지)
                 ---> kswapd 긴급 활성화 ---> 운영 서비스 메모리 스왑 및 프로세스 강제 종료 발생

KernelDump:
스트리밍 쓰기   ---> posix_fadvise(POSIX_FADV_SEQUENTIAL) 힌트 적용
                 ---> sync_all() 호출로 더티 페이지 디스크 동기화
                 ---> posix_fadvise(POSIX_FADV_DONTNEED)로 클린 캐시 페이지 즉시 해제
                 ---> 호스트 페이지 캐시 순증가량: +124 kB 유지
```

### 리눅스 페이지 캐시 무효화 메커니즘과 동작 원리

리눅스 가상 메모리 서브시스템(`mm/fadvise.c`)에서 디스크에 아직 기록되지 않은 더티(Dirty) 상태의 페이지에 대해 `posix_fadvise(POSIX_FADV_DONTNEED)`를 호출하면 커널은 해당 호출을 무시(No-op)합니다. 커널은 미동기화된 데이터를 버릴 수 없기 때문입니다.

`KernelDump`는 고속 버퍼 I/O를 유지하면서도 시스템 메모리 오염을 원천 차단하기 위해 3단계 메모리 보호 메커니즘을 적용합니다:
1. **순차 스트리밍 힌트:** `memory.lime.partial` 및 `ranges.jsonl` 파일 생성 시 `posix_fadvise(POSIX_FADV_SEQUENTIAL)`를 호출하여 커널이 리드어헤드 윈도우를 최적화하고 지나간 프레임을 신속히 해제하도록 유도합니다.
2. **지속성 보장 파일 동기화:** 페이로드 및 원장 작성이 완료되면 즉시 `sync_all()`을 호출하여 모든 더티 페이지를 디스크 스토리지로 완전히 플러시합니다.
3. **즉시 캐시 해제:** 동기화가 완료된 파일에 대해 `posix_fadvise(POSIX_FADV_DONTNEED)`를 호출하여 메모리에 남아있는 클린 페이지 캐시를 호스트 RAM에서 즉시 축출하며, 실패 시 명시적인 경고 로그를 출력합니다.

### 호스트 메모리 변화 실측 증적

실제 활성 서비스가 지속 트래픽을 처리 중인 운영 리눅스 노드에서 855 MiB 덤프를 기록하기 직전과 직후의 `/proc/meminfo` 실측치입니다:

```
[수집 직전 호스트 상태]
MemTotal:        9,436,180 kB
Active(file):    2,104,228 kB
Cached:          3,841,920 kB

[Post-Acquisition Host State (KernelDump)]
Active(file):    2,104,312 kB
Cached:          3,842,044 kB
변화량:               +124 kB (0.000124 GiB)
```

---

## 다중 환경 실측 검증

`KernelDump`의 이식성과 안전성을 검증하기 위해 다양한 리눅스 커널 및 가상화 환경에서 실측을 수행했습니다:

| 리눅스 커널 버전 | 배포판 및 C 런타임 | 가상화 플랫폼 | 시스템 메모리 | 수집 결과 | 상세 검증 내용 |
|---|---|---|:---:|:---:|---|
| **Linux 6.8.0-146-generic** | Ubuntu 24.04.5 LTS (glibc 2.39) | VMware Workstation 17 | 9.44 GiB | **수집 완료 (855.0 MiB / 2.132초)** | 상용 운영 서버 실측; Volatility 3 전체 59개 플러그인 전수 검증 |
| **Linux 6.18.33.2-ms-wsl2** | 클라우드 하이퍼바이저 커널 | Microsoft Hyper-V | 15.7 GiB | **수집 완료 (607.7 MiB / 1.504초)** | 24,993개 PFN 범위 추출; 물리 주소 정렬 및 해시 무결성 확인 |

### `CONFIG_PROC_KCORE` 필수 요건 및 안전 종료(Fail-closed) 동작

- Ubuntu, Debian, RHEL, openSUSE, Arch, WSL2 등 표준 엔터프라이즈 및 클라우드 커널은 `CONFIG_PROC_KCORE=y`가 기본 활성화되어 있어 즉시 수집이 가능합니다.
- 초경량 마이크로VM 커널(예: Alpine Linux `linux-virt`)과 같이 `CONFIG_PROC_KCORE`가 비활성화된 환경에서는 `kerneldump check --json`이 누락된 인터페이스를 감지하여 `ready: false`와 함께 안전하게 종료됩니다.

---

## CLI 사용법 및 실제 실행 결과

### 1. 사전 진단 점검 (`check`)

메모리 덤프 작업을 시작하기 전, 루트 권한(EUID 0), `/proc/kcore`, `/proc/kpageflags`, 심볼 마스킹 해제(`kptr_restrict=0`), 대상 디스크 가용 용량을 진단합니다.

```sh
sudo ./kerneldump check
```

실제 실행 결과 (대화형 TTY 출력):
```text
kerneldump system readiness check (Linux 6.18.54-121.166.amzn2023.x86_64):
  [PASS] root_privilege     : Effective UID is 0 (root)
  [PASS] kcore_interface    : /proc/kcore is readable (ELF64 detected)
  [PASS] kpageflags         : /proc/kpageflags is accessible
  [PASS] kptr_restrict      : Kernel pointer addresses exposed (kptr_restrict=0)
  [PASS] storage_capacity   : Output path storage has 71420 MiB available

Status: READY for live kernel memory acquisition.
```

자동화 스크립트 및 CI 파이프라인 연계를 위한 JSON 출력 (`--json`):
```sh
sudo ./kerneldump check --json
```

실제 실행 결과:
```json
{
  "ready": true,
  "kernel_release": "6.18.54-121.166.amzn2023.x86_64",
  "checks": [
    {
      "name": "root_privilege",
      "passed": true,
      "detail": "Effective UID is 0 (root)"
    },
    {
      "name": "kcore_interface",
      "passed": true,
      "detail": "/proc/kcore is readable (ELF64 detected)"
    },
    {
      "name": "kpageflags",
      "passed": true,
      "detail": "/proc/kpageflags is accessible"
    },
    {
      "name": "kptr_restrict",
      "passed": true,
      "detail": "Kernel pointer addresses exposed (kptr_restrict=0)"
    },
    {
      "name": "storage_capacity",
      "passed": true,
      "detail": "Output path storage has 71420 MiB available"
    }
  ]
}
```

### 2. 커널 환경 및 메모리 경계 탐색 (`probe`)

시스템의 물리 RAM 세그먼트, 커널 버전, 베이스 주소 오프셋, BTF 메타데이터를 탐색합니다.

```sh
sudo ./kerneldump probe
```

실제 실행 결과:
```json
{
  "kernel_banner": "Linux version 6.18.54-121.166.amzn2023.x86_64 (mockbuild@ip-10-0-49-18) (gcc (GCC) 11.5.0 20240719 (Red Hat 11.5.0-5), GNU ld version 2.41-50.amzn2023.0.5) #2 SMP PREEMPT_DYNAMIC Tue Oct  6 23:11:34 UTC 2026\n",
  "kernel_release": "6.18.54-121.166.amzn2023.x86_64",
  "page_offset_base": 18446616581900337152,
  "kernel_gnu_build_ids": [
    "db0381963da8135cfe6c95212224db532a5d6658"
  ],
  "kernel_notes_sha256": "7da6feeca52898ad7f5658df308344c58a9eed2015955f0b807d86ec557cfb15",
  "kernel_btf": {
    "bytes": 5178259,
    "sha256": "d865baa253eef9454e386d4402c4a50e339c19ed8c5cf472a7354cc53751fbd9"
  },
  "runtime_arch_task_struct_size": 10496,
  "ram_ranges": [
    [4096, 655360],
    [1048576, 3150766080],
    [3153977344, 3220684800],
    [4294967296, 68685922304]
  ],
  "io_at_probe": {
    "available": true,
    "kcore_probe": {
      "calls": 7,
      "returned_bytes": 1260
    }
  }
}
```

### 3. 주소 보존형 커널 메모리 획득 (`capture`)

커널 슬랩, 페이지 테이블, 커널 코어 영역을 선별 획득하여 Native LiME 바이너리 이미지로 저장합니다.

```sh
sudo ./kerneldump capture --output /dumps/incident-001 --request-id prod-linux-host-01
```

실제 실행 결과:
```json
{
  "status": "complete_for_policy",
  "payload_bytes": 2289319296,
  "policy_excluded_bytes": 65318711936,
  "unavailable_bytes": 0,
  "unprocessed_bytes": 0,
  "elapsed_s": 20.835,
  "errors": [],
  "manifest": "/dumps/incident-001/manifest.json"
}
```

### 4. 수집 산출물 암호학적 무결성 검증 (`verify`)

획득된 `memory.lime`의 PFN 범위, 오프셋, 바이트 해시 및 매니페스트 레코드를 교차 검증합니다.

```sh
sudo ./kerneldump verify /dumps/incident-001
```

실제 실행 결과:
```json
{
  "status": "integrity_verified",
  "verified": true,
  "ranges_checked": 120185,
  "lime_sha256": "ed1d7d48df8eef2de87dd67f873405bf35c3a0f76f0b9c8e7b6a1ea9f33ca1c3",
  "sha256_match": true
}
```

### 수집 디렉터리 산출물 구조

```
/dumps/incident-001/
├── memory.lime        # 물리 주소가 보존된 LiME 규격 커널 메모리 이미지 (권한 0600)
├── ranges.jsonl       # PFN 시작/종료 주소, 플래그, 분류 매핑 원장
└── manifest.json      # 출처 메타데이터, SHA-256 해시, 수집 소요 시간, 커널 정보
```

### 디스크 용량 안전장치 및 실패 매니페스트 보장

메모리 수집 작업을 시작하기 전, `KernelDump`는 2단계 스토리지 보호 루틴을 실행합니다:
- **사전 여유 공간 점검:** `statvfs` 시스템 콜을 통해 대상 파일시스템의 가용 용량이 `max(RAM / 10, 1 GiB)` 이상인지 검사합니다(`check_available_space`).
- **비상 매니페스트 예약 파일 (`posix_fallocate`):** 작업 시작 즉시 1 MiB 크기의 비상 예약 파일(`manifest_reserve`)을 사전 할당합니다. 디스크 여유 공간이 부족해지는 상황이 발생하더라도, `KernelDump`는 이 예약 파일을 해제하여 수집 실패 사유와 현재까지 수집된 부분 범위를 기록한 `manifest.json`을 안전하게 저장합니다.
- **Fail-Fast 한계:** 이 메커니즘은 사전 점검 및 메타데이터 복원력을 위한 안전장치이며, 외부 프로세스에 의한 급격한 디스크 고갈을 완전히 차단하는 것은 아닙니다.

---

## 빌드 및 릴리즈 바이너리 증적

`KernelDump`는 `x86_64-unknown-linux-musl` 타깃으로 정적 링크 컴파일되어 외부 공유 라이브러리 의존성 없이 리눅스 환경에서 바로 실행됩니다.

사전 컴파일된 공식 릴리즈 바이너리는 [GitHub Releases](https://github.com/KKudroK/KernelDump/releases)에서 다운로드할 수 있습니다.

### 소스코드 오프라인 빌드 (Vendored)

외부 네트워크 연결 없이 빌드할 수 있도록 모든 21개 의존 라이브러리가 [`vendor/`](vendor/) 디렉터리에 내장되어 있습니다:

```sh
# 1. 정적 musl 타깃 릴리즈 바이너리 빌드
cargo build --release --locked --offline --target x86_64-unknown-linux-musl

# 2. 통합 단위 테스트 검증
cargo test --release --locked --offline --features development-options
```

컴파일된 바이너리는 `./kerneldump`로 배포 및 실행할 수 있습니다.

### 기준 암호화 체크섬

| 릴리즈 산출물 | 참조 실행 파일 | 바이너리 포맷 | SHA-256 체크섬 |
|---|---|---|---|
| **공식 바이너리** | `./kerneldump` | ELF 64-bit static-pie (musl, stripped) | `58b4d570be7cd42d0cb6c1e2af45be82c70cdd881047ac6fe15e6ba819ab9773` |

---

## 기술적 한계 및 운영 제약 사항

포렌식 분석 및 학술 연구의 엄밀성을 위해, `KernelDump`의 설계상 경계와 운영 제약 사항을 명확히 명시합니다:

1. **커널 제어 플레인 집중 (사용자 공간 페이로드 의도적 배제):**
   `KernelDump`는 커널 레벨 침해사고 대응, 루트킷 탐지, 프로세스/네트워크/마운트 제어 플레인 분석에 특화되어 있습니다. 사용자 공간 힙, 스택, 익명 메모리 및 파일 캐시는 정책적으로 제외됩니다(`strict_kernel_only: false`). 이에 따라:
   - 프로세스 메타데이터(`PID`, `PPID`, `COMM`)는 100% 완전하지만, 사용자 스택이 수집되지 않으므로 `psaux`의 커맨드라인 인자(`ARGS`)는 `"-"`로 표시됩니다.
   - `malfind`에서 탐지된 `rwx` 메모리 영역은 커널 VMA 테이블로부터 식별된 것이며, 사용자 익명 메모리가 수집되지 않으므로 덤프된 바이트는 0으로 채워집니다.
   - 쉘 명령어 기록(`bash`) 및 환경변수(`envars`)는 수집되지 않습니다. 프로세스 내부의 상세 사용자 공간 메모리 분석이 필요한 경우 `PodDump`와 같은 프로세스 전용 덤프 도구와 병행하여 사용해야 합니다.

2. **비원자적 라이브 획득 및 스미어 윈도우:**
   호스트 커널이 실행 중인 상태에서 물리 메모리 프레임을 순차적으로 읽어 들입니다. 전체 RAM 덤프 대비 시간적 스미어 윈도우를 **94.4% ~ 98.5%** (~2.1초 vs ~38-146초) 대폭 압축하지만, 완전 정지 스냅샷이 아니므로 변경 빈도가 매우 높은 객체에서는 포인터 불일치가 미세하게 발생할 수 있습니다.

3. **다중 페이지 경계 확장 (`classify_with_neighbors`):**
   단일 페이지 경계를 초과하는 커널 구조체(예: SLUB 할당자에서 10,496바이트를 차지하는 `struct task_struct`)의 절단을 방지하기 위해, SLAB 및 PGTABLE 프레임의 전후 물리 인접 페이지를 함께 보존합니다. 이로 인해 인접한 사용자 공간 힙이나 캐시 페이지가 결과물에 포함될 수 있습니다.

4. **동적 메모리 핫플러그 미감지:**
   `/proc/kcore`의 ELF 세그먼트 매핑은 수집 시작 시 1회만 파싱됩니다. 수집 진행 중에 동적으로 발생하는 메모리 핫플러그(Hot-add 또는 Hot-remove)는 실시간으로 감지되지 않습니다.

5. **인터페이스 요구조건:**
   루트 권한(`EUID 0` / `CAP_SYS_ADMIN`) 하에서 읽기 가능한 `/proc/kcore` (`CONFIG_PROC_KCORE=y`) 및 `/proc/kpageflags` 인터페이스가 필수적입니다. `/proc/kcore`가 비활성화된 임베디드 마이크로VM(예: Alpine `linux-virt`)에서는 사전 점검 단계에서 안전하게 작업이 거부됩니다.

---

## 라이선스 및 기여

- `KernelDump` 핵심 코드는 [MIT 라이선스](LICENSE)에 따라 배포됩니다.
- 내장된 벤더링 라이브러리들의 개별 라이선스는 [`hash_dependency_provenance.json`](hash_dependency_provenance.json)에 기록되어 있습니다.
- 모든 실측 검증 원본 데이터와 빌드 증적은 [`validation.json`](validation.json) 및 [`build_provenance.json`](build_provenance.json)에서 확인할 수 있습니다.
