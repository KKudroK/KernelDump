# KernelDump

2026-11-05 소스 수정으로 수집 누락과 소속 판정 문제를 보완했습니다. [수정 내용과 검증 범위](docs/capture_review.md)를 참고하세요. 아래의 기존 릴리즈 수집 결과와 성능 수치는 이전 빌드의 기록입니다.

[v1.3.0 릴리스](https://github.com/KKudroK/KernelDump/releases/tag/v1.3.0)는 코드·네트워크·메모리 파일의 추가 수집 기회를 고르게 나누고, 소유 관계와 무관하게 바뀌는 페이지 플래그 때문에 자료를 버리던 검증을 보완했습니다. 실패한 참조의 실제 주소와 값도 기록합니다. [변경 내용과 검증 범위](docs/release_v1_3_0.md)를 참고합니다. 실행 파일과 릴리스 버전은 모두 1.3.0이며 정책은 `kernel-focused-v9`입니다.

추가 경로의 팀 로컬 VM 검증과 한도는 [닫힌 FD memfd 검증](docs/scenario2_memfd_20261104.md)을 따릅니다. [기존 Linux 7.0 검증](docs/kernel_7_0_0_38_validation.md)과 아래 성능 수치는 당시 빌드의 기록입니다. v1.2.1의 AWS Pod 수집 결과와 새 바이너리의 준비 검사는 구분합니다.

[English](README.md) · [배포 조건](docs/deployment.md) · [원본 대비 실측](docs/original_comparison.md) · [릴리즈 파일](docs/release_v1_2_2.md)

`kerneldump`는 `/proc/kcore`와 `/proc/kpageflags`로 실행 중인 커널 메모리를 선별 수집합니다. 커널 모듈 설치나 프로세스 정지 없이 LiME 이미지, 주소·수집 범위 원장과 manifest를 만듭니다.

## 실행

Linux x86-64 정적 바이너리 하나로 실행합니다. 수집 시 별도 런타임 라이브러리·심볼·설정 파일이 필요하지 않습니다.

```sh
chmod 755 kerneldump
sudo ./kerneldump check --target-dir /evidence --json
sudo ./kerneldump capture --output /evidence/new_collection
./kerneldump verify /evidence/new_collection
```

`/evidence`는 기존 디렉터리, `new_collection`은 새 경로여야 합니다. `check`는 커널 접근과 임시 파일 생성·동기화·정리를 검사합니다. 저장소를 지정하지 않거나 검사에 실패하면 준비 실패를 반환합니다. 검사 통과는 공간 예약을 뜻하지 않습니다.

kcore/page monitor를 제공하는 커널과 필수 인터페이스·가려지지 않은 심볼에 대한 읽기 권한이 필요합니다. kcore가 없는 환경은 지원하지 않으며 보안 설정을 자동 변경하지 않습니다. [필수 조건과 실패 처리](docs/deployment.md).

현재 v9 배포본의 수집 출력 예시입니다. 핵심 항목만 표시했습니다. 수집 시간 비교는 아래 표를 따릅니다.

```json
{
  "status": "complete_for_policy",
  "payload_bytes": 656162816,
  "unavailable_bytes": 0,
  "unprocessed_bytes": 0,
  "errors": []
}
```

같은 수집본의 검증 결과:

```json
{
  "verified": true,
  "status": "complete_for_policy",
  "coverage_ranges": 12300,
  "payload_bytes": 656162816
}
```

[수집 stdout](docs/examples/capture_v9.stdout) · [검증 stdout](docs/examples/verify_v9.stdout).

## Pod 지정

```sh
sudo ./kerneldump capture --pod <전체_Pod_UID> --output /evidence/new_collection
```

분석 Pod를 지정하려면 `--pod`에 이름 대신 전체 Pod UID를 넣습니다. 생략하면 노드 전체에서 제한된 추가 수집을 수행합니다. 지정하면 코드·소켓·선택한 캐시의 **추가 탐색만** 해당 Pod로 좁힙니다. 기존 커널 관리 정보의 수집 범위는 유지합니다. 따라서 전체 덤프가 그 Pod의 자료만 담는 것은 아닙니다.

현재 cgroup 경로, PID와 프로세스 시작 시간을 함께 확인합니다. Pod를 찾지 못하거나 호스트의 PID·cgroup 관점이 아니면 수집을 거부하며, 노드 전체 수집으로 바꾸지 않습니다. 수집 중 소속이나 실행 식별 정보가 바뀌면 불완전 수집으로 남깁니다. 이미 Pod cgroup을 떠난 프로세스의 과거 소속까지 찾지는 않습니다.

## 실행 코드·통신·파일 캐시

`kernel-focused-v9`은 별도 옵션 없이 다음 내용을 추가 보존합니다.

- **실행 코드**: private 실행 영역의 익명 페이지. 파일 코드를 수정한 사본과 파일 없이 만든 실행 코드가 포함됩니다. 현재 쓰기 권한은 필요하지 않습니다. 정상 JIT도 포함되므로 수집 자체는 공격 판정이 아닙니다.
- **통신 대기 내용**: 열린 파일에서 찾은 소켓의 수신·송신 큐, TCP 재전송·순서 외 수신 트리, UDP의 별도 읽기 대기 목록(`reader_queue`). 큐마다 최대 64KiB를 고르고, 여러 페이지의 조각과 `frag_list`도 따라갑니다. 과거의 전체 통신은 아닙니다.

**Pod를 지정하면 일부 파일 캐시도 보완합니다.** 열린 memfd·tmpfs 파일과 삭제 후 열린 일반 파일은 크기가 커도 앞 64KiB까지 메모리에 남은 내용을 고릅니다. FD가 닫힌 공유 memfd도 VMA와 address_space.i_mmap 연결을 확인하며, 실행 코드의 비교용 파일 페이지도 찾습니다. FD·maps·VMA·COW 작업은 종류마다 최대 128개를 허용하고 번갈아 처리합니다. 수집 대상이 아닌 일반 파일은 FD 작업 한도를 쓰기 전에 제외합니다. 역방향 VMA는 매핑마다 64개까지 확인합니다. 디스크를 읽어 빠진 내용을 올리지 않으며, 현재 연결이나 비교 캐시를 과거 통신·최초 원본의 증거로 보지 않습니다.

memfd 후보를 찾는 proc maps 읽기는 소켓 탐색이 끝난 뒤 캐시 단계에서 주소 공간마다 한 번 수행하며, 파일마다 512KiB로 제한합니다. 이 읽기도 캐시의 4MiB 및 100ms 예산에 포함합니다. proc에서 얻은 범위, 파일 오프셋, inode 번호가 실제 공유 VMA와 링크 없는 shmem inode에 일치해야 수집합니다. 역방향 매핑에는 공유 또는 사유 매핑 여부, 파일 바이트 범위, 관측한 프로세스 리더의 task 주소, PID, 시작 시간을 기록합니다. 프로세스 식별값과 mm 연결은 본문 읽기 전후에 재검증합니다. 소유자 목록이 비어 있으면 미확인을 뜻하며, 탐색 요약은 원장의 검증 결과와 함께 해석해야 합니다. 공유 범위가 겹친다는 사실만으로 실제 데이터 교환을 증명하지는 않습니다.

코드·네트워크·캐시는 중복을 제거한 후보 합계 **4,096페이지·추가 본문 최대 16MiB**를 공유하며 세 종류에 번갈아 기회를 줍니다. 코드와 자원 탐색은 각각 협력적 1초를 쓰고, 캐시는 별도의 100ms·읽기 요청 4MiB를 씁니다. 캐시 후보는 관리 정보 포함 256페이지까지입니다. 관리 구조체 페이지도 공통 후보 한도를 사용합니다. JSON 기록·수집기 메모리·기존 덤프 전체를 16MiB로 제한한다는 뜻은 아닙니다. 한도와 누락 이유를 기록하며 진행 중인 커널 읽기를 강제로 끊는 시간 제한은 아닙니다.

네트워크의 구조체 크기와 필드 위치는 실행 커널의 `/sys/kernel/btf/vmlinux`에서 읽습니다. 별도 ISF는 수집기에 필요하지 않습니다. Pod 지정 여부와 관계없이 스레드의 개별 FD 표를 확인하고 공유 표는 중복 탐색하지 않습니다. 프로세스 대표 4,096개, 그룹당 스레드 4,096개, 전체 스레드 16,384개로 탐색을 제한합니다. 전역 소켓 표는 훑지 않습니다. 선택한 코드 주소만 Maple Tree에서 조회하고, 필요한 파일 위치만 XArray에서 찾습니다. 이 경로는 Ubuntu 6.8 VM에서 검증했으며 다른 커널 전체의 호환성을 뜻하지 않습니다.

읽기 전후 확인한 참조가 달라지거나 전체 한도로 후보를 놓치면 `partial`입니다. 큐별 64KiB 제한은 수집 정책의 범위로 따로 기록합니다. 큰 실행 영역이 있으면 중요한 코드 페이지도 빠질 수 있습니다. 같은 값의 전후 관측이나 `complete_for_policy`가 모든 증거·동일 시점을 보장하지는 않습니다. 자세한 판단과 실측은 [수집 범위와 비용](docs/resource_retention.md)을 따릅니다.

## 원본 대비 수집 시간과 덤프 크기

익명 실행 페이지·네트워크·캐시의 추가 탐색이 없던 **v4**와 현재 **v9**를 같은 VM·같은 시험 자료·같은 저장소에서 비교했습니다. 구성별 3회 중앙값이며, 덤프 크기는 압축 전 LiME 파일 전체입니다.

| 항목 | 원본 v4 | 현재 v9 · Pod 미지정 | 현재 v9 · Pod 지정 |
|---|---:|---:|---:|
| 수집 시간 | 10.11 s | 9.88 s | 9.72 s |
| 최종 LiME 파일 | 617.64 MiB | 615.01 MiB | 621.64 MiB |
| 원장·manifest 포함 | 622.97 MiB | 620.28 MiB | 626.58 MiB |
| CPU 시간 합 | 9.06 s | 9.90 s | 9.25 s |
| 최대 수집기 메모리 | 11.00 MiB | 11.25 MiB | 11.38 MiB |
| 기존 필터에 더한 본문 | 0.00 KiB | 8.00 KiB | 28.00 KiB |
| 수집 상태 | 완료 3/3 | partial 3/3 | 완료 3/3 |

Pod 지정 기준으로 **수집 시간은 10.11초 → 9.72초(-0.39초), 최종 덤프는 617.64MiB → 621.64MiB(+4.01MiB)**였습니다. 시간 범위는 원본 9.14~10.43초, Pod 지정 9.46~9.85초로 겹치므로 빨라졌다고 단정하지 않습니다.

전체 덤프 증가분을 모두 새 기능의 비용으로 해석하면 안 됩니다. 실행 중인 커널 상태가 달라지는 영향도 섞여 있습니다. 같은 수집에서 기존 필터에 실제로 더한 본문은 Pod 지정 시 **28KiB**, 미지정 시 **8KiB**였습니다. Pod 미지정 3회는 노드의 일부 통신 참조가 읽기 전후에 달라져 `partial`로 기록됐습니다. 9회 모두 저장 파일의 무결성 검증은 통과했으며, 무결성 통과와 참조의 일관성은 별개입니다.

종료 전 VM 노드에는 디스크 공간 경고(`DiskPressure`)가 있었습니다. 실행 중인 Pod와 재시작 횟수는 유지됐지만 서비스 지연은 측정하지 않았습니다.

[조건·한계·실행별 수치](docs/original_comparison.md).

## 과거 릴리즈 검증 환경

아래 검증은 추가 수집 이전 v4의 기록입니다. 새 BTF·자원 탐색의 호환성 검증으로 확대하지 않습니다.

아래 환경에 동일한 x86-64 릴리즈 바이너리를 사용했습니다.

| 환경 | 커널 | 결과 |
|---|---|---|
| Ubuntu 24.04.5 | 6.8.0-147 | ext4에서 수집·검증 성공 |
| Ubuntu 26.04, WSL2 | 6.18.33.2 | ext4에서 수집·검증 성공 |
| Debian 12 | 6.1.0-53-cloud-amd64 | 수집·검증 성공; ext4, cgroup v2 |
| Debian 13 | 6.12.111+deb13-cloud-amd64 | 수집·검증 성공; ext4, cgroup v2 |
| Rocky Linux 8.10 | 4.18.0-553.el8_10.x86_64 | 수집·검증 성공; xfs, cgroup v1 |
| Rocky Linux 9.8 | 5.14.0-687.10.1.el9_8.0.1.x86_64 | 수집·검증 성공; xfs, cgroup v2 |
| Kali Rolling (cloud 2026.2) | 6.18.12+kali-cloud-amd64 | 수집·검증 성공; ext4, cgroup v2 |
| Alpine 3.16.9, cgroup v1 | 5.15.148 | 실행 가능, kcore 부재로 수집 불가 |
| Alpine 3.22.6, cgroup v2 | 6.12.110 | 실행 가능, kcore 부재로 수집 불가 |

Rocky는 SELinux Enforcing을 유지하고 unconfined 도메인에서 sudo로 실행했습니다. Alpine은 kcore가 없었고, WSL의 Windows 공유 저장소는 사적 권한 검사에 실패했습니다. [검증 조건](docs/distro_validation.md).

Kali cloud 이미지의 배포명은 2026.2이며, 내부 `VERSION_ID`는 2026.1입니다.

## AWS 비교

AWS EC2 `r6i.2xlarge`에서 측정한 기록입니다. Amazon Linux 2023, Linux 6.18.54, RAM 61.78 GiB, gp3 저장소를 사용했습니다. 16 GiB를 할당해 페이지마다 쓴 뒤 메모리에 유지했습니다. 반복 측정값은 평균 ± 표본 표준편차입니다.

| 도구 | 횟수 | 이미지 크기 | 명령 경과 시간 | 호스트 캐시 증가 |
|---|---:|---:|---:|---:|
| LiME, 전체 RAM | 1 | 62.965 GiB | 466.93 s | 40.19 GiB |
| makedumpfile `-d 31` | 5 | 2.37 ± 0.62 GiB | 1.48 ± 0.25 s* | 2.37 ± 0.62 GiB |
| **KernelDump** | **5** | **1.99 ± 0.17 GiB** | **20.84 ± 1.78 s** | **110 ± 65 KiB** |

KernelDump 이미지는 전체 RAM LiME보다 **96.8% 작았고**, 관측된 캐시 증가가 작으며 별도 LiME 변환이 필요하지 않았습니다.

*makedumpfile 시간에는 수집 후 sync가 포함되지 않고, KernelDump에는 내구 저장 완료가 포함됩니다. 따라서 같은 저장 완료 기준의 속도 비교는 아닙니다. 수집 정책과 시점도 다르며, AWS 측정은 v0.1.1 이전 기록입니다. [측정 방법과 원자료](docs/benchmark_summary.md).

## Volatility 3 분석

Volatility **2.28.0**, Debian 12 / Linux **6.1.0-53**, 일치하는 DWARF 심볼과 4단계 페이지 테이블에서 시험했습니다. 전체본과 그 바이트를 그대로 선별한 수집본을 비교해 선별 손실과 분석기 오류를 구분했습니다.

| 결과 | 플러그인 | 확인 내용 |
|---|---|---|
| 커널 메타데이터 확인 | `pslist`, `pstree`, `sockstat`, `lsof`, `lsmod`, `mountinfo`, `ip`, `kmsg`, `ebpf` | 전체본과 같은 레코드; 시험 소켓 5개 모두 유지 |
| 프로세스 메모리 내용 제외 | `psaux`, `envars`, `elfs`, `library_list`, `vmaregexscan` | 인자·환경변수·ELF 헤더·프로세스 버퍼는 수집 정책에서 제외 |
| 불완전한 입력으로 결과 변화 | `process_spoofing` | 명령행 부재로 `True`가 `False`로 바뀔 수 있음; `False`는 위장 없음의 근거가 아님 |
| 파일 메타데이터 보존, 내용 제한 | `pagecache.Files`, `pagecache.RecoverFs` | 경로·inode는 일치하지만 제외한 파일 캐시 때문에 내용의 완전한 복구는 불가 |
| 미수집 구간의 분석 호환성 한계 | `psscan` | 누락 페이지 읽기 예외로 스캔 중단; 실제 릴리즈 수집본에서도 재현 |
| 전체 RAM에서도 실패 | `sockscan`, `capabilities`, `kallsyms` | 분석기 오류로, 선별 때문이라고 단정할 수 없음 |

`malfind`, `check_creds` 등의 빈 출력은 탐지 성공으로 세지 않았습니다. 분석에는 커널에 맞는 심볼이 필요하며, 수집은 여전히 실행 파일 하나로 가능합니다. [59개 실행 결과와 원인 상세](docs/plugin_compatibility.md).

**`psscan`의 한계:** KernelDump가 제외한 페이지는 수집본에 공백으로 남습니다. 동일 바이트 비교에서는 Volatility가 잘못된 프로세스 후보를 검사하다 이 공백을 읽었고, 누락 페이지 예외를 처리하지 않아 스캔이 중단됐습니다. 전체본에서 해당 후보의 종료 상태와 PID는 `-1`이었으므로, 이 최초 실패가 실제 유효 프로세스 누락을 뜻하지는 않습니다. 공백은 KernelDump의 선별로 생기고, 분석 전체 중단은 분석기의 공백 처리에서 발생합니다. 선별본의 `psscan` 동작은 보장하지 않으며, `pslist`도 숨김·잔존 프로세스 검색을 대신하지 않습니다. 이 오류를 피하려고 주변 페이지나 수집 옵션을 추가하지 않습니다.

## 산출물과 종료 상태

- `memory.lime`: 물리 주소를 유지한 선별 메모리.
- `ranges.jsonl`: 수집·제외·읽기 실패 범위.
- `manifest.json`: 정책, 원본 식별 정보, 오류와 파일 해시.

종료 **0**은 기록된 정책에 따른 수집·저장 완료, **2**는 불완전 수집 또는 준비 실패, **1**은 명령·준비·검증·저장 오류입니다. stderr와 일부 파일을 보존하세요. 수집은 원자적이지 않으며 취소는 협력적입니다. SIGKILL 뒤에는 최종 manifest가 없을 수 있습니다.

## 빌드와 확인

```sh
./kerneldump --version
./kerneldump --build-info
# 현재 배포본 빌드: Rust 1.93.0 + x86_64-unknown-linux-musl 타깃
python3 scripts/build_release.py
```

버전 **1.3.0**. `release/kerneldump`, `release/manifest.json`, `release/SHA256SUMS.txt`를 만듭니다. 빌드 정보에는 소스 해시와 실제 실행 파일의 해시가 기록됩니다. [릴리즈 검증](docs/release_validation.md) · [이전 문서](docs/history_readme_20261017_ko.md).

MIT 라이선스이며, vendored 의존성은 각 라이선스를 유지합니다.
