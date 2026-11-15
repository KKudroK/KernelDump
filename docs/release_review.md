# 릴리스 검증

`kerneldump 1.4.0`(`prod-hardening` 브랜치)은 오프라인 코드·빌드 검사, 정적 `musl` 바이너리 무결성, 단순 CLI 검사, 지역 WSL2(`ext4`) 환경의 반례 검증(`1db4019` vs 기본 수집 vs `--extended`), 3회 교차 측정, `rrudrok 0.5.0` 분석 호환 검증을 모두 통과했습니다. `main` 병합과 공개 릴리스 여부는 사용자 결정에 따라 진행합니다.

## 1. 정적 빌드와 코드 검사

오프라인 환경에서 아래 검사를 모두 통과했습니다.

- `cargo fmt --check`, `cargo clippy --offline --locked --all-targets -- -D warnings`, `python3 scripts/build_release.py --check-vendor` 통과
- `cargo test --offline --locked`, `cargo test --offline --locked --release`, `x86_64-unknown-linux-musl` 정적 릴리스 테스트 각각 **103개 통과, 실패 0개**
- 배포 바이너리(`1,383,472`바이트, SHA-256 `a295f81f09e7eb05d5d3bd5ce1ae06d61d7a20be77506b0fedfa3e34418ae4ed`) 확인: 외부 공유 라이브러리 없이 정적 연결(`statically linked`), 기능 플래그 비어 있음(`features: []`), 배포 `manifest.json`의 소스 20개 SHA-256 전부 현재 소스와 일치(자세한 해시는 배포 `manifest.json`과 `SHA256SUMS.txt` 참조)

## 2. 단일 명령과 기본/확장 두 가지 모드 CLI 검증

정적 배포 바이너리는 `kerneldump --output <새_폴더> [--extended]`와 `-h`/`--help`, `-V`/`--version`만 제공합니다. 도움말·버전 출력과 중복 `--extended`, 제거된 하위 명령(`capture`), 제거된 `--pod` 옵션 거부를 확인했습니다.

## 3. 반례 검증·3회 교차 측정·`rrudrok` 호환 검증

개선판(`v1.4.0`)은 `address_space.i_pages` XArray 트리를 직접 순회(`MAX_XA_NODES_PER_FILE = 16,384`)해 `16 MiB` 파일 앞부분 자름을 없앴고, 소켓 대기열 안전 상한을 `64 KiB`에서 **`16 MiB`**로 올렸으며, 큐·후보 상한에 걸리면 `issues`와 `status: "partial"`(종료 코드 `2`)을 남깁니다. 또한 기본 수집(`default`, `i_nlink == 0`)과 `--extended` 확장 수집(링크가 남은 `tmpfs` `0x01021994` 추가 보존)으로 모드를 분리했습니다(`filter.policy = "kernel-focused-v9"` 유지).

지역 WSL2 커널(`6.18.33.2-microsoft-standard-WSL2`, `ext4`)에서 `32 MiB memfd`(0 MiB·20 MiB 지점 증인), `192 KiB` TCP 수신 대기열, 열린 FD `tmpfs`, 닫힌 FD `MAP_SHARED tmpfs`, 삭제 후 열린 파일, CoW·익명 실행 페이지와 함께 `384 MiB` `ext4` 배경 파일 프로세스를 두고 비교했습니다.

- **이전 후보(`1db4019`) 반례**: `memfd 20 MiB` 지점을 `policy_excluded`로 제외했고, `192 KiB` TCP 수신 대기열도 `[32,767, 32,769]`(`65,536`B)에서 잘려 뒷부분 증인이 빠졌지만(`policy_window_truncations: 2`), `issue_count: 0`, `complete_for_policy`(종료 코드 `0`)로 보고했습니다.
- **개선판 기본 수집 (`--output DIR`)**: `rc=0`, `complete_for_policy`, `retention_mode: "default"`, `policy_window_truncations: 0`, `issue_count: 0`을 기록했습니다. `memfd` 0 MiB·20 MiB, `196,608 B`(`192 KiB`) TCP 수신 대기열 전체(분할 물리 페이지 재조합 100% 일치), 삭제 후 열린 파일·CoW·익명 실행 페이지를 모두 복원했고, 일반 `tmpfs`와 `384 MiB` `ext4` 배경 파일(`noise_pid_file_cache_pages: 0`, `ext4_noise: 0`)은 제외했습니다.
- **개선판 확장 수집 (`--output DIR --extended`)**: 기본 수집 항목 전체에 더해 `/dev/shm` 일반 `tmpfs` 열린 FD와 닫힌 FD `MAP_SHARED` VMA 증인까지 모두 복원하면서도 `ext4` 배경 파일은 그대로 제외했습니다(`noise_pid_file_cache_pages: 0`, `ext4_noise: 0`).

| 버전/모드 | 3회 중앙값 수집 시간 | 논리 파일 크기 | 실제 디스크 할당 | Sparse 0 절약 |
|---|---:|---:|---:|---:|
| `main` (`v1.3.0`) | 3,132.8 ms | 1,158,084,416 B | 1,158,090,752 B | 0 B |
| 개선판 기본 (`--output`) | 8,207.66 ms | 1,216,247,776 B | 1,052,975,104 B | 222,277,632 B |
| 개선판 확장 (`--extended`) | 7,829.467 ms | 1,131,277,600 B | 975,777,792 B | 211,447,808 B |

`v1.4.0`은 XArray 전체 순회, `16 MiB` 소켓 큐 검사, 0 페이지 Sparse 저장과 직후 구조 검사(`verify_fast`)까지 한 명령에서 수행해 실제 디스크 사용량을 줄이면서도 `main`이 놓치던 `20 MiB+ memfd`와 긴 TCP 대기열을 복원합니다. (위 수치는 WSL2 `ext4` 모의 부하 환경 측정값이며, 이전 EC2 기록과는 별개입니다.)

- **`rrudrok 0.5.0` 분석 호환**: PodDump Core(`Pod` cgroup 1개)와 KernelDump 확장 수집본, ISF(타입 16,441개, 심볼 197,535개)를 함께 `analyze --verify-hashes`로 분석해 **오류 0건, 경고 0건, 분석 후 해시 검증 일치, 레코드 53,745건**을 확인했습니다. `show` 6종(`summary`, `pods`, `processes`, `net`, `files`, `drift`)과 `read-memory` 3종(Core 가상 주소, 커널 물리 `0x1000`, `linux_banner`)도 정상 종료했습니다.

검증에 사용한 임시 덤프와 작업 폴더는 확인 직후 모두 삭제했습니다.

## 4. 배포 전 확인 상태

소스 검증, 정적 musl 릴리스 빌드, WSL2 반례·교차 비교와 `rrudrok` 호환 검증, 임시 덤프 정리를 마쳤습니다. `main` 병합과 공개 릴리스만 사용자 확인 후 진행합니다.

