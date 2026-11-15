# KernelDump 코드와 수집 원리

KernelDump는 커널 모듈 없이 Linux의 메모리 읽기 파일과 BTF를 사용해 커널 중심 메모리를 수집합니다. 기본 사용 명령은 [README](../README.md)에 있습니다.

## 수집 순서

1. `main`과 `source::preflight`가 저장소에 쓸 수 있는지 검사합니다. `btf`가 실행 중인 커널의 필수 자료 위치(`task_struct`, `files_struct`, `mm_struct`, `vm_area_struct`, `inode`, `sock`)를 읽고, kcore·kpageflags·RAM 범위·심볼 접근을 확인합니다.
2. `source`가 PFN 상태로 수집 범위를 고릅니다. PFN은 물리 메모리 페이지의 번호입니다. SLAB·페이지 테이블과 그 주변 등을 유지하고 일반 사용자 메모리·일반 파일 캐시 등은 정책에 따라 제외합니다.
3. `code_pages`·`resources`·`resources/cache`가 노드 전체에서 조건에 맞는 추가 근거를 보탭니다.
   - `code_pages`: private 실행 매핑(`r-xp`)의 익명/COW 페이지
   - `resources`: 소켓 대기열 및 TCP 재전송·비순차 큐(큐별 64KiB 한도)
   - `resources/cache`: 링크가 끊긴 일반 파일(`i_nlink == 0`, 파일별 최대 16MiB)의 열린 FD 및 커널 VMA 트리(`mm_mt`/`mm_rb`) 직접 탐색 기반 공유 `memfd` VMA, 그리고 COW 실행 코드 페이지에 대응하는 원본 파일 캐시 페이지
   일반 링크 파일(`i_nlink != 0`, 일반 `tmpfs` 포함)은 제외합니다. 비정상 폭주를 막기 위한 안전 상한(합계 512MiB, 단계별 5초)에 걸리거나 읽기 오류가 발생하면 `issues`와 `partial`로 남기고, 비정지 수집 중 실행 프로세스나 소켓 상태가 바뀐 경우(`same_pfn: false`, `same_fields: false`, 읽기 직전 해제)는 `ranges.jsonl`과 `live_drift`에 구분해 기록합니다.
4. `capture`가 고정 4MiB 단위로 읽고 깊이 2 파이프라인으로 별도 쓰기 작업에 전달합니다. 모든 0 페이지는 Sparse 방식으로 저장하고 논리 바이트 전체로 SHA-256을 계산합니다.
5. 파일을 동기화하고 게시한 뒤 `verify::verify_fast`가 헤더·범위 기록·카운터를 확인합니다. 완료 상태는 `complete_for_policy`이며 CLI 표준 출력에는 `verification_mode: "fast_structural"`을 표시합니다.

프로세스와 커널은 수집 중 계속 실행됩니다.

## 구조 검사

수집 완료 직후 `verify_fast`가 LiME 헤더, 범위 기록 해시, PFN 플래그, 파일 길이, `live_drift`와 수집 카운터를 검증합니다(`verify_fast` 내부 모드 이름 `fast_header_ledger`, CLI 출력 `verification_mode: "fast_structural"`, `payload_hash_verified: false`). 전체 메모리 바이트와 `lime_sha256` 대조는 분석 단계에서 수행합니다.

실행 명령은 `kerneldump --output NEW_DIR`, `-h`/`--help`(무인자 포함), `-V`/`--version`만 제공합니다.

## Sparse와 페이지 캐시 제어

LiME 헤더는 32바이트이며 물리 주소와 구간 길이를 기록합니다. 본문을 4KiB씩 검사해 모두 0이면 파일 위치만 옮깁니다. 파일을 다시 읽으면 같은 0바이트가 나옵니다. AVX2 지원 여부는 실행 중 확인하고, 미지원 CPU에서는 일반 비교를 사용합니다.

- `file_bytes`: Sparse 구간을 포함한 논리 파일 길이
- `allocated_file_bytes`: 파일 시스템이 실제 할당한 크기
- `sparse_zero_hole_bytes`: 쓰지 않고 건너뛴 0바이트 수
- `actual_written_bytes`: LiME 헤더와 실제 쓴 본문 바이트 수

16MiB 창마다 `sync_file_range`와 `POSIX_FADV_DONTNEED`를 요청합니다. 이들은 페이지 캐시를 줄이기 위한 힌트입니다. 저장 완료는 별도의 파일·디렉터리 동기화와 `RENAME_NOREPLACE` 게시로 확인합니다.

## 파일별 역할

| 파일 | 담당 |
|---|---|
| `src/main.rs` | 최소 CLI 검사(`--output`, `-h`/`--help`, `-V`/`--version`) 및 준비·수집·검증 연결 |
| `src/source.rs` | 사전 점검, RAM 범위, kcore 주소, PFN 필터, 추가 근거 통합 |
| `src/btf.rs` | 실행 커널의 BTF에서 자료 크기·필드 위치 읽기 |
| `src/code_pages.rs` | 노드 전체 익명/COW 실행 코드 후보 및 `CowTarget` 생성 |
| `src/resources.rs` | 노드 전체 프로세스·스레드 순회, 소켓 큐와 네트워크 후보, 참조 검증 |
| `src/resources/cache.rs` | 순수 BTF VMA 탐색(`mm_mt`/`mm_rb`), `i_nlink == 0` unlinked/memfd 캐시·COW 비교 캐시 |
| `src/capture.rs` | 읽기·쓰기 작업, 버퍼 재사용, Sparse, manifest |
| `src/rate_limit.rs` | 본문 쓰기 평균 속도 제어 구현 |
| `src/verify.rs` | 수집 직후 구조 검증(`verify_fast`) 및 테스트용 전체 검증(`verify`) |
| `src/ledger.rs` | JSONL 범위 기록과 레코드 크기 제한 |
| `src/safe_output.rs` | 안전한 출력, 저장소 검사, 캐시 힌트, AVX2 검사 |
| `build.rs`, `src/build_info.rs` | 소스·의존성·빌드 정보(ELF 내장 및 manifest 기록) |

커널 구조체의 필드 위치는 현재 BTF에서 읽습니다. 특정 커널 버전의 위치를 다른 버전에 그대로 적용하지 않습니다. 한 경로의 필드를 해석하지 못하면 해당 추가 수집의 문제를 기록합니다.

## 검증 범위

배포 전 clippy(`-D warnings`), 단위·회귀 테스트, 형식 검사, vendor 해시 검증, musl 정적 릴리스 빌드를 수행합니다. Sparse 전체 해시, LiME 헤더, 변조 검출, 순수 BTF `mm_mt`/`mm_rb` 탐색, `i_nlink > 0` 일반/tmpfs 파일 제외, 쓰기 실패·panic 복구를 검사합니다.

[이전 후보판 측정](history_codebase_candidate.md)은 과거 기준 기록이며, 최신 배포 검사 결과는 [릴리스 검증](release_review.md)에 기록합니다.
