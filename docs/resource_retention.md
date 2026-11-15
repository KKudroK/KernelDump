# 노드 전체 조건 기반 추가 증거 수집

**일반 디스크 파일 캐시 전체는 수집하지 않는다. 노드 전체에서 조건에 맞는 추가 근거만 보완한다.** 기존처럼 별도 Pod 지정(`--pod`)을 요구하지 않으며, 기본 수집(`--output DIR`)과 확장 수집(`--output DIR --extended`) 두 가지 모드로 동작한다.

```sh
# 기본 수집
sudo ./kerneldump --output /evidence/new_collection

# 확장 수집 (링크가 남아 있는 tmpfs 상주 페이지 추가)
sudo ./kerneldump --output /evidence/new_collection_ext --extended
```

이 문서는 현재 구현의 조건 기반 노드 전체 선택 정책을 설명한다. 과거 `--pod` 기반 4,096페이지(16MiB)·64KiB 상한 측정 이력은 [v8 검증](history_resource_retention_v8.md)과 [실행별 수치·검증](resource_retention_results.json)에 남아 있다.

## 무엇을 추가하는가

| 대상 | 고르는 조건과 범위 | 제외하는 대상 |
|---|---|---|
| 링크가 끊긴 정규 파일·`memfd` | 노드 전체에서 열린 FD 또는 공유 `memfd` VMA 중 `i_nlink == 0`인 파일의 XArray 상주 페이지(파일 앞부분 16MiB 잘림 없음) | 비상주(swap/미할당) 페이지 |
| 링크가 남은 `tmpfs` (`--extended` 전용) | `--extended` 지정 시 `s_magic == 0x01021994`(`tmpfs`, `/dev/shm`, `emptyDir: Memory`)의 열린 FD 또는 `MAP_SHARED` VMA 상주 페이지 | 기본 모드에서는 전체 제외, 디스크 파일 시스템(`ext4`/`xfs`/`overlayfs`)은 두 모드 모두 제외 |
| 수정 실행 코드 (`r-xp`) | 노드 전체 프로세스의 private 실행 매핑 중 익명·COW 물리 페이지 | 읽기 전 교체되었거나 swap/비상주 페이지 |
| 소켓 대기 내용 | BTF로 연결한 소켓의 수신·송신·TCP 재전송·비순차 큐, 큐별 최대 16MiB(`MAX_QUEUE_SKBS = 16,384`, 전체 `65,536`) | 빈 큐 |
| COW 코드 비교 캐시 | 발견한 private 실행 COW 페이지와 1:1로 대응하는 원본 파일 캐시 페이지 | 일반 읽기 전용 데이터 캐시 전체 |

FD는 프로세스가 열어 둔 파일의 번호다. FD만 있고 메모리 구간에 매핑하지 않은 `memfd`나 삭제 후 열린 파일, 반대로 FD를 닫은 뒤 `MAP_SHARED`로 매핑만 남긴 `memfd`(확장 모드에서는 링크가 남은 `tmpfs`도 포함)를 모두 수집 대상에 넣는다. 비교용 캐시는 **현재 메모리에 남은 파일 내용**이며 차이가 있다는 사실만으로 공격이라고 판정하지 않는다.

## 구조를 따라가는 방법

- **열린 FD 파일**: `init_task`에서 모든 리더와 스레드의 `files_struct`를 따라가며 `file.f_inode`에서 `S_ISREG`와 `i_nlink`·`s_magic`을 확인한다. 기본 모드에서는 `i_nlink != 0`이면 즉시 제외하고, `--extended` 모드에서는 `i_nlink == 0` 또는 `s_magic == 0x01021994`만 통과시킨다.
- **FD 없는 공유 VMA 및 COW 대응**: `/proc/<pid>/maps`를 다시 열지 않고 `task_struct.mm`의 Maple Tree(`mm_mt`) 또는 RB Tree(`mm_rb`)를 BTF로 직접 순회한다. 이 방식으로 호스트 PID 네임스페이스와 컨테이너 PID 네임스페이스 간 번호 차이에 영향받지 않고 `VM_SHARED` 매핑과 `r-xp` COW 매핑을 짝짓는다.
- **역매핑 및 XArray 직접 순회**: `address_space.i_mmap`에서 역매핑 소유자를 확인하고 `address_space.i_pages` XArray 트리를 `walk_xa_node`로 위에서 아래로 직접 순회(노드당 64슬롯 512B 일괄 읽기)해 이미 상주 중인 페이지만 `/proc/kcore`로 읽는다. `hugetlbfs`는 미지원 오류로 구분해 남긴다.

## 안전 상한 (Runaway 방어용)

| 항목 | 내부 안전 상한 |
|---|---|
| 코드·통신·캐시 추가 후보 합계 | 중복 제거 뒤 131,072페이지 (최대 512MiB, 초과 시 `shared_retention_budget`) |
| 캐시 전용 후보 | 최대 65,536페이지 (최대 256MiB) |
| 소켓 큐별 대기열 | 큐별 최대 16MiB / 16,384 `sk_buff`, 전체 65,536 `sk_buff` (초과 시 `queue_window_truncation`) |
| 파일당 XArray 노드 탐색 | 파일당 최대 `MAX_XA_NODES_PER_FILE = 16,384` 노드 (고정 파일 크기 자름 없음) |
| 단계별 탐색·검증 시간 상한 | 5초 (`code_pages` 5초, `resources` 5초, `cache` 5초, 사후 참조 검증 5초) |
| 캐시 탐색 및 참조 검증 읽기 한도 | 캐시 읽기 요청 64MiB, 종류별 최대 4,096작업, `mm`당 Maple 노드 최대 4,096개, 참조 검증 64MiB |

정상 다중 Pod 노드에서는 위 상한에 걸리지 않고 조건에 맞는 대상을 보존한다. 상한 도달이나 읽기 오류처럼 수집기 자체가 못 읽거나 잘린 경우는 `issues`와 `status: "partial"`(종료 코드 `2`)로 남기며 `complete_for_policy`로 보고하지 않는다. 프로세스 정지 없이 수집하는 도중 V8 JIT 매핑 재할당이나 소켓 큐 변경·페이지 해제처럼 대상 상태가 바뀐 경우는 `ranges.jsonl`(`same_pfn`/`same_fields`)과 `live_drift`(`released_before_read_pages`)에 사실대로 기록한다.
