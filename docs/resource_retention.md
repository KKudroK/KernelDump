# 노드 전체 조건 기반 추가 증거 수집

**일반 파일 캐시 전체는 수집하지 않는다. 노드 전체에서 조건에 맞는 추가 근거만 빠짐없이 보완한다.** 기존처럼 별도 Pod 지정(`--pod`)을 요구하지 않으며, 다중 Pod·다중 노드 환경에서도 노드 전체에서 실행 코드, 소켓 대기열, 링크가 끊긴 파일·`memfd` 캐시, COW 비교 캐시를 함께 확보한다.

```sh
sudo ./kerneldump --output /evidence/new_collection
```

이 문서는 현재 구현의 조건 기반 노드 전체 선택 정책을 설명한다. 과거 `--pod` 기반 4,096페이지(16MiB)·64KiB 상한 측정 이력은 [v8 검증](history_resource_retention_v8.md)과 [실행별 수치·검증](resource_retention_results.json)에 남아 있다.

## 무엇을 추가하는가

| 대상 | 고르는 조건과 범위 | 제외하는 대상 |
|---|---|---|
| 링크가 끊긴 일반 파일·`memfd` | 노드 전체에서 열린 FD 또는 공유 `memfd` VMA 중 `i_nlink == 0`, 파일별 최대 16MiB의 상주 페이지 | 디스크에 경로 링크가 남은 일반 파일(`i_nlink != 0`, 호스트 `/run`, `/dev/shm` 등 일반 `tmpfs` 포함) |
| 수정 실행 코드 (`r-xp`) | 노드 전체 프로세스의 private 실행 매핑 중 익명·COW 물리 페이지 | 읽기 전 교체되었거나 swap/비상주 페이지 |
| 소켓 대기 내용 | BTF로 연결한 소켓의 수신·송신·TCP 재전송·비순차 큐, 큐별 최대 64KiB | 빈 큐, 큐 한도 초과분 |
| COW 코드 비교 캐시 | 발견한 private 실행 COW 페이지와 1:1로 대응하는 원본 파일 캐시 페이지 | 일반 읽기 전용 데이터 캐시 전체 |

FD는 프로세스가 열어 둔 파일의 번호다. FD만 있고 메모리 구간에 매핑하지 않은 `memfd`나 삭제 후 열린 파일, 반대로 FD를 닫은 뒤 `MAP_SHARED`로 매핑만 남긴 `memfd`를 모두 수집 대상에 넣는다. 비교용 캐시는 **현재 메모리에 남은 파일 내용**이며 차이가 있다는 사실만으로 공격이라고 판정하지 않는다.

## 구조를 따라가는 방법

- **열린 FD 파일**: `init_task`에서 모든 리더와 스레드의 `files_struct`를 따라가며 `file.f_inode`에서 `i_nlink == 0`과 정규 파일 여부(`S_ISREG`)를 확인한다. `i_nlink != 0`이면 파일 시스템 종류와 무관하게 즉시 제외한다.
- **FD 없는 공유 `memfd` VMA 및 COW 대응**: `/proc/<pid>/maps`를 다시 열지 않고 `task_struct.mm`의 Maple Tree(`mm_mt`) 또는 RB Tree(`mm_rb`)를 BTF로 직접 순회한다. 이 방식으로 호스트 PID namespace와 다른 컨테이너 PID namespace 간 번호 차이에 영향받지 않고 `VM_SHARED` + `i_nlink == 0` + `tmpfs` 매핑과 `r-xp` COW 매핑을 짝짓는다.
- **역매핑 및 페이지 캐시**: `address_space.i_mmap`에서 역매핑 소유자를 확인하고 `address_space.i_pages` XArray에서 이미 상주 중인 페이지만 `/proc/kcore`로 읽는다. hugetlbfs는 미지원 오류로 구분해 남긴다.

## 안전 상한 (Runaway 방어용)

| 항목 | 내부 안전 상한 |
|---|---|
| 코드·통신·캐시 추가 후보 합계 | 중복 제거 뒤 131,072페이지 (최대 512MiB) |
| 캐시 전용 후보 | 최대 65,536페이지 (최대 256MiB) |
| 파일별 보존 범위 | 파일별 최대 16MiB (`i_size > 16MiB`이면 `file_prefix_retained`) |
| 단계별 탐색·검증 시간 상한 | 5초 (`code_pages` 5초, `resources` 5초, `cache` 5초, 사후 참조 검증 5초) |
| 캐시 탐색 및 참조 검증 읽기 한도 | 캐시 읽기 요청 64MiB, 종류별 최대 4,096작업, `mm`당 Maple 노드 최대 4,096개, 참조 검증 64MiB |

정상 다중 Pod 노드에서는 위 상한에 걸리지 않고 조건에 맞는 대상을 100% 보존합니다. 상한 도달이나 읽기 오류처럼 수집기 자체가 못 읽은 경우는 `issues`와 `partial`로 구분해 남기고, 프로세스 정지 없이 수집하는 도중 V8 JIT 매핑 재할당이나 소켓 큐 변경·페이지 해제처럼 대상 상태가 바뀐 경우는 `ranges.jsonl`(`same_pfn`/`same_fields`)과 `live_drift`(`released_before_read_pages`)에 사실대로 기록합니다.
