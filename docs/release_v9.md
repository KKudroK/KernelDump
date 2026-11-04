# v9 릴리즈 파일

아래 해시와 배포 묶음은 2026-11-04 재점검 이전 빌드의 이력이다. 수정 후 실행 파일과 해시는 로컬 release 폴더에서 확인하고, [수정 내용과 검증 범위](fixes_20261104.md)를 함께 참고한다.

재점검 이전 실행 파일의 SHA-256은 b16a6ad7419f3e6bc2e7871a2362a9e849af1a3129b72458fb1a6018b4fa2fe0이다. 아래 배포 목록과 압축 파일 해시는 이 이전 빌드를 가리킨다.

GitHub Release 업로드용 파일은 로컬 저장소의 `release_assets/`에 있다.

- `kerneldump-v0.1.1-policy-v9-linux-x86_64.tar.gz`: 실행 파일·빌드 출처·사용법·라이선스·의존성 고지·내부 체크섬
- `SHA256SUMS.txt`: 압축 파일 체크섬
- `RELEASE_NOTES.md`: 릴리즈 본문에 붙일 설명

프로그램 버전은 0.1.1, 수집 정책은 `kernel-focused-v9`다. 기존 태그와 구분하려면 릴리즈 태그로 `v0.1.1-policy-v9`를 사용할 수 있다. 파일은 준비된 상태이며 GitHub Release 게시와 commit/push는 수행하지 않았다. 생성된 `release/`와 `release_assets/`는 저장소의 기존 ignore 규칙을 유지하며, Release 첨부 파일로 올린다.

```sh
sha256sum -c SHA256SUMS.txt
mkdir kerneldump-v9
tar -xzf kerneldump-v0.1.1-policy-v9-linux-x86_64.tar.gz -C kerneldump-v9
cd kerneldump-v9
sha256sum -c SHA256SUMS.txt
```

첫 검사는 내려받은 압축 파일, 두 번째 검사는 압축 안의 실행 파일과 부속 파일을 확인한다. 압축 파일 SHA-256: `08df4af06e5d54196c726e460ee620420cc8b42b63e522185021fbef95a2c846`. 압축 내부의 실행 권한과 각 파일의 실제 바이트도 확인했다.

[원본 대비 수집 비용](original_comparison.md) · [수집 범위](resource_retention.md).
