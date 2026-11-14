# KernelDump 코드와 수집 원리

KernelDump는 커널 모듈 없이 Linux의 메모리 읽기 파일과 BTF를 사용해 커널 중심 메모리를 수집합니다. 기본 사용 명령은 [README](../README.md)에 있습니다.

## 수집 순서

1. `main`과 `safe_output`이 저장소에 쓸 수 있는지 검사합니다. `btf`가 실행 중인 커널의 필수 자료 위치를 읽고, `source`가 kcore·kpageflags·RAM 범위·심볼 접근을 확인합니다.
2. `--pod`가 있으면 호스트 PID·cgroup namespace인지 먼저 확인합니다. 전체 Pod UID와 현재 프로세스 소속을 대조합니다. `--allow-exited-pod`는 현재 소속 프로세스가 없을 때 기본 커널 수집을 허용할 뿐, 과거 존재나 종료를 증명하지 않습니다.
3. `source`가 PFN 상태로 수집 범위를 고릅니다. PFN은 물리 메모리 페이지의 번호입니다. SLAB·페이지 테이블과 그 주변 등을 유지하고 일반 사용자 메모리·파일 캐시 등은 정책에 따라 제외합니다.
4. `code_pages`·`resources`·`resources/cache`가 실행 코드, 소켓 대기 내용, 일부 파일 캐시 후보를 보탭니다. 세 종류가 합계 4,096페이지, 본문 최대 16MiB 한도를 공유합니다. 빠진 후보나 바뀐 참조는 결과에 남깁니다.
5. `capture`가 기본 4MiB 단위로 읽고 별도 쓰기 작업에 전달합니다. 사용한 버퍼를 최대 32개까지 재사용합니다. 모든 0 페이지는 Sparse 방식으로 저장하고 논리 바이트 전체로 SHA-256을 계산합니다.
6. 파일을 동기화하고 게시한 뒤 `verify_fast`가 헤더·범위 기록·카운터를 확인합니다. 완료 상태는 `complete_for_policy`입니다.

프로세스와 커널은 수집 중 계속 실행됩니다. `--pod`가 있어도 기본 커널 범위는 노드 전체이며 추가 탐색만 해당 Pod로 좁힙니다.

## 구조 검사와 전체 검사

| 검사 | 실행 | 확인하는 내용 |
|---|---|---|
| `fast_header_ledger` | 수집 완료 직후 자동 | LiME 헤더, 범위 기록 해시, PFN 플래그, 파일 길이와 수집 카운터 |
| `full_sha256` | `kerneldump verify --output DIR` | 위 항목과 실제 메모리 본문·전체 파일 SHA-256 |

구조 검사 결과는 `payload_hash_verified: false`입니다. 저장된 본문 한 바이트가 변해도 구조 검사를 통과할 수 있습니다. 전체 검사는 그 변경을 거부합니다. `verified: true`만 보지 말고 검사 종류도 함께 봐야 합니다. 전체 검사는 커널 메모리를 다시 읽지 않으며 결과 파일에 쓰지 않습니다.

기본 수집 명령은 `kerneldump --output NEW_DIR`입니다. 기존 스크립트를 위해 `check --target-dir DIR [--json]`, `capture --output NEW_DIR`, `probe`, `verify DIR`도 유지합니다. `check`만 통과한 것은 수집 완료가 아닙니다.

## Sparse와 쓰기 속도

LiME 헤더는 32바이트이며 물리 주소와 구간 길이를 기록합니다. 본문을 4KiB씩 검사해 모두 0이면 파일 위치만 옮깁니다. 파일을 다시 읽으면 같은 0바이트가 나옵니다. AVX2 지원 여부는 실행 중 확인하고, 미지원 CPU에서는 일반 비교를 사용합니다.

- `file_bytes`: Sparse 구간을 포함한 파일 길이
- `allocated_file_bytes`: 파일 시스템이 실제 할당한 크기
- `sparse_zero_hole_bytes`: 쓰지 않고 건너뛴 0바이트 수
- `actual_written_bytes`: LiME 헤더와 실제 쓴 본문 바이트 수

`rate_limit::RateLimiter`는 실제 본문 쓰기의 평균 속도를 제한합니다. 필요한 시간 동안 20ms 단위로 반복 대기하며 취소를 확인합니다. 헤더·범위 기록·파일 시스템 자체 쓰기는 제한값에 포함되지 않습니다. 짧은 구간에는 쓰기 묶음 때문에 순간 속도가 높을 수 있습니다.

16MiB 창마다 `sync_file_range`와 `POSIX_FADV_DONTNEED`를 요청합니다. 이들은 페이지 캐시를 줄이기 위한 힌트입니다. 저장 완료는 별도의 파일·디렉터리 동기화와 `RENAME_NOREPLACE` 게시로 확인합니다.

## 파일별 역할

| 파일 | 담당 |
|---|---|
| `src/main.rs` | 명령 검사, 준비·수집·검증 연결, 이전 명령 호환 |
| `src/source.rs` | RAM 범위, kcore 주소, PFN 필터, 호스트 namespace 검사 |
| `src/btf.rs` | 실행 커널의 BTF에서 자료 크기·필드 위치 읽기 |
| `src/pod_scope.rs` | 전체 Pod UID와 현재 프로세스 소속 대조 |
| `src/code_pages.rs` | 일부 익명 실행 코드 후보 |
| `src/resources.rs` | 소켓 큐와 네트워크 후보, 참조 검증 |
| `src/resources/cache.rs` | memfd·삭제 후 열린 파일·코드 비교용 캐시 후보 |
| `src/capture.rs` | 읽기·쓰기 작업, 버퍼 재사용, Sparse, manifest |
| `src/rate_limit.rs` | 실제 본문 쓰기 평균 속도와 취소 대기 |
| `src/verify.rs` | 구조 검사와 전체 SHA-256 검사 |
| `src/ledger.rs` | JSONL 범위 기록과 레코드 크기 제한 |
| `src/safe_output.rs` | 안전한 출력, 저장소 검사, 캐시 힌트, AVX2 검사 |
| `build.rs`, `src/build_info.rs` | 소스·의존성·실행 파일 해시 |

커널 구조체의 필드 위치는 현재 BTF에서 읽습니다. 특정 커널 버전의 위치를 다른 버전에 그대로 적용하지 않습니다. 한 경로의 필드를 해석하지 못하면 해당 추가 수집의 문제를 기록합니다.

## 검증 범위

배포 전 기본·개발 옵션의 clippy와 test, 형식, vendor 해시, musl 정적 빌드를 검사합니다. Sparse 전체 해시, LiME 헤더, 변조 검출, 0.25초보다 긴 속도 제한, 대기 취소, namespace 거부, 쓰기 실패·panic 복구를 검사합니다.

[이전 후보판 측정](history_codebase_candidate.md)의 수치와 99개 테스트는 해당 후보판의 기록입니다. 기존 3단계 명령과 새 기본 명령의 전체 시간에는 검사 범위 차이가 포함됩니다. 최신 배포 검사 결과는 [릴리스 검증](release_review.md)에 기록합니다.
