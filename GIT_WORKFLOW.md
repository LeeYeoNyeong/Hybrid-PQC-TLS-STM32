# Git Workflow

이 저장소의 분기(branching) 전략과 커밋 규칙입니다. 경량 GitHub Flow를 기반으로 하며, 단독 또는 소규모 개발에 맞게 간소화되어 있습니다.

## 핵심 원칙

| 원칙 | 이유 |
|------|------|
| `main`은 항상 빌드·플래시 가능한 상태 유지 | 언제든 측정을 재현할 수 있어야 논문/리포트 신뢰성이 유지됨 |
| 브랜치 하나 = 주제 하나 | 실패한 실험을 격리하고 리뷰 가능한 diff를 유지 |
| 브랜치 수명 짧게 (수 시간~며칠) | `main`과의 divergence 최소화 |
| merge 후 로컬·원격 브랜치 삭제 | 저장소를 깔끔하게 유지 |
| 실험은 `experiment/` 접두사 | `main`에 들어가지 않을 수도 있음을 명시 |

## 브랜치 네이밍

| 접두사 | 용도 | 예시 |
|--------|------|------|
| `feat/<주제>` | 새 기능 | `feat/sphincs-tls-wiring` |
| `fix/<주제>` | 버그 수정 | `fix/eth-link-flap` |
| `docs/<주제>` | 문서 | `docs/git-workflow` |
| `chore/<주제>` | 빌드·도구·CI | `chore/cmake-preset-tweak` |
| `perf/<주제>` | 성능 개선 | `perf/falcon-stack-reduction` |
| `refactor/<주제>` | 동작 변경 없는 정리 | `refactor/scenario-table-split` |
| `experiment/<주제>` | 성공이 불확실한 실험 | `experiment/liboqs-port` |

짧은 영어 소문자 + 하이픈 사용. 한글이나 공백은 피합니다.

## 커밋 메시지 규칙 (Conventional Commits)

```
<type>(<scope 선택>): <요약 한 줄, 50자 이내>

<본문 — 왜 이 변경이 필요한지, 어떤 결정을 내렸는지>

Co-Authored-By: ... (선택)
```

**type**: `feat`, `fix`, `docs`, `chore`, `perf`, `refactor`, `test`, `build`
**scope** (선택): `wolfssl`, `benchmark`, `freertos`, `lwip` 등

좋은 예:
```
feat(wolfssl): align Falcon/SPHINCS+ codepoints with oqs-provider 0.12
fix(benchmark): prevent SNTP blocking when NTP server silent
docs: add CLAUDE.md project guide
```

## 표준 워크플로우

### 1. 브랜치 시작

```bash
git checkout main
git pull --ff-only origin main
git checkout -b feat/<주제>
```

### 2. 작업하며 의미 단위로 커밋

```bash
git add <변경된 파일들>
git commit -m "feat(wolfssl): add SPHINCS case to PickHashSigAlgo switch"
```

- 한 커밋 = 한 논리 단위
- 컴파일 통과 상태로 커밋 (`cmake --build build/Debug`)
- 가능하면 변경 직후 테스트(플래시 + 벤치마크 1 라운드) 수행

### 3. 원격 푸시 + upstream 설정

```bash
git push -u origin feat/<주제>
```

### 4. PR 생성 (GitHub CLI 사용)

```bash
gh pr create \
  --base main \
  --title "feat(wolfssl): SPHINCS+ TLS 1.3 wiring" \
  --body "## 요약
- PickHashSigAlgo에 sphincs_fast_level1 case 추가
- SendCertificateVerify 경로 분기 연결
- ClientHello signature_algorithms에 0xFEC2 광고 확인

## 검증
- [ ] Round 측정 errors=0
- [ ] mean time 기록

closes #N"
```

제목은 최종 커밋 메시지(merge 후 `main` 히스토리)가 될 수 있도록 짧고 명확하게.

### 5. 자기-리뷰 후 Merge

단독 개발자인 경우:

```bash
# 1단계: 로컬에서 빌드·플래시·벤치마크 재확인
cmake --build build/Debug && STM32_Programmer_CLI -c port=SWD \
  -w build/Debug/Test_pqc_tls.elf -rst

# 2단계: squash merge (기능 단위로 한 커밋이 되도록)
gh pr merge --squash --delete-branch
```

`--squash`는 브랜치 내 여러 WIP 커밋을 하나의 의미 있는 커밋으로 압축. `main` 히스토리가 깔끔해집니다.

### 6. 로컬 정리

```bash
git checkout main
git pull --ff-only origin main
git branch -d feat/<주제>   # --delete-branch 로 원격은 이미 지워짐
```

## 실험(`experiment/*`) 브랜치 운영

- `main`에 **merge하지 않을 수도** 있음
- 부분 성공한 조각만 나중에 `feat/*`로 재정리해서 별도 PR로 올림
- 실패한 실험이라도 브랜치는 보관 (배움용). 정리하고 싶으면 태그 후 삭제:
  ```bash
  git tag archived/experiment-<주제> <브랜치 커밋 SHA>
  git push origin archived/experiment-<주제>
  git branch -D experiment/<주제>
  git push origin --delete experiment/<주제>
  ```

## 되돌리기(Revert) 정책

- `main`에 merge된 커밋은 **되돌리기 전에 이슈/메모** 남기기
- `git revert <SHA>` 사용 (히스토리 rewrite 금지)
- 이미 push된 `main`에 `reset --hard`·`force-push` 금지

## PR 체크리스트 (템플릿)

PR 생성 시 본문에 아래 항목 포함을 권장합니다:

```markdown
## 요약
- 변경 요지 1~3줄

## 검증
- [ ] cmake --build build/Debug 성공
- [ ] Flash + UART 로그에서 정상 부팅 확인
- [ ] 해당 시나리오 errors=0 (측정한 평균 ms 명시)
- [ ] 기존 시나리오에 regression 없음

## 관련 이슈 / 참고
- 이슈 번호 또는 커밋 SHA
```

## 예시: 이번 세션을 재구성한다면

| 브랜치 | 대응 변경 |
|--------|-----------|
| `docs/claude-md` | `CLAUDE.md` 추가 |
| `fix/sntp-blocking-fallback` | `tls_client.c`의 SNTP 우회 부분 |
| `feat/panic-handlers` | `stm32f4xx_it.c` + `freertos.c` panic 출력 |
| `feat/scenario-skip-list` | `tls_client.c`의 `g_skip_scenarios[]` |
| `feat/wolfssl-falcon-codepoint-align` | Falcon OID/codepoint/hash 일체 |
| `experiment/wolfssl-sphincs-tls-wiring` | SPHINCS+ 관련 (완결 미정) |

→ 각 브랜치가 독립적으로 revert/cherry-pick 가능한 단위가 됩니다.
