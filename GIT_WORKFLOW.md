# Git Workflow

이 저장소의 분기(branching) 전략과 커밋 규칙입니다.  
경량 GitHub Flow 기반, 단독·소규모 개발 최적화.

> **2026-04-28 개정** — 4가지 운영 문제(머지 전략 혼재 / 브랜치 미정리 / worktree 방치 / 거대 PR) 해소를 위해 전면 갱신.

---

## GitHub Repository 설정 (최초 1회)

Settings → General → Pull Requests:

| 항목 | 설정값 | 이유 |
|------|--------|------|
| Allow squash merging | ✅ ON | main 히스토리를 PR 단위 단일 커밋으로 유지 |
| Allow merge commits | ❌ OFF | merge commit과 squash 혼재 방지 |
| Allow rebase merging | ❌ OFF | 동일 이유 |
| Automatically delete head branches | ✅ ON | 머지 후 원격 브랜치 자동 삭제 |

---

## 핵심 원칙

| 원칙 | 이유 |
|------|------|
| `main`은 항상 빌드·플래시 가능 상태 | 언제든 측정 재현 가능 → 논문/리포트 신뢰성 |
| 브랜치 하나 = 이슈 하나 = 주제 하나 | 실패한 실험 격리, 리뷰 가능한 diff 유지 |
| 브랜치 수명 짧게 (수 시간~며칠) | `main`과의 divergence 최소화 |
| 머지 후 로컬·원격 브랜치 즉시 삭제 | 저장소 노이즈 방지 |
| 데이터 산출물(로그·PNG·txt)은 코드와 별도 PR | 거대 커밋 방지, bisect 가능성 보존 |

---

## 브랜치 네이밍 (Issue 번호 필수)

```
<type>/#<Issue번호>-<slug>
```

| type | 용도 | 예시 |
|------|------|------|
| `feat` | 새 기능 | `feat/#25-instrumentation` |
| `fix` | 버그 수정 | `fix/#10-falcon-hardfault` |
| `perf` | 성능 개선 | `perf/#30-sphinx-yield-tuning` |
| `refactor` | 동작 변화 없는 정리 | `refactor/#31-scenario-table-split` |
| `docs` | 문서만 변경 | `docs/#32-git-workflow-update` |
| `chore` | 빌드·도구 | `chore/#33-cmake-preset-tweak` |
| `experiment` | 성공 불확실한 실험 | `experiment/wolfssl-oqs-port` |

- `experiment/`는 Issue 번호 생략 가능 (main merge 안 할 수도 있음)
- slug는 짧은 영어 소문자 + 하이픈. 한글·공백 금지
- **Issue 없이 브랜치 생성 금지** — 먼저 `gh issue create`

---

## 커밋 메시지 규칙 (Conventional Commits)

```
<type>(<scope>): <요약, 50자 이내>

<본문 — 왜 이 변경인지, 어떤 결정을 내렸는지 (#N)>
```

**허용 type** (이 목록 외 사용 금지):

| type | 용도 |
|------|------|
| `feat` | 새 기능·시나리오 추가 |
| `fix` | 버그·오류 수정 |
| `perf` | 성능 개선 |
| `refactor` | 동작 변화 없는 코드 정리 |
| `docs` | 문서·주석만 변경 |
| `chore` | 빌드·도구·설정 변경 |
| `test` | 테스트 추가·수정 |
| `build` | CMake·링커 스크립트 변경 |

> `harden`, `add`, `update` 등 비표준 type 사용 금지.  
> 하드닝·강건화는 `fix` 또는 `refactor`로 표현.

**scope** (권장 목록):

`wolfssl` · `tls` · `kem` · `matrix` · `parser` · `graphs` · `freertos` · `lwip` · `sphincs` · `falcon` · `bench` · `instrumentation` · `uart` · `cmake` · `session`

좋은 예:
```
feat(instrumentation): add cert-chain DER size + heap watermark (#25)
fix(wolfssl): guard encryptionOn for TLS 1.3 msg_callback (#26)
docs(session): update Phase C WIP progress
```

나쁜 예:
```
harden(review): explicit ret on Falcon goto paths   ← 비표준 type
feat: add stuff                                      ← scope 없음, 설명 부족
Update session_progress.md                           ← Conventional Commits 미준수
```

---

## .gitignore 우선 점검 (작업 시작 전 필수)

새 작업을 시작하기 **전에** 아래를 확인한다. 한 번이라도 `git add`로 잘못된 파일이 들어가면 히스토리에서 완전히 제거하기 어렵다.

### 추적 제외 파일 분류 기준

| 분류 | 예시 | 이유 |
|------|------|------|
| **IDE 개인 설정** | `.settings/`, `.clangd`, `*.launch`, `.mxproject` | 개인 환경 종속, `.ioc`로 재생성 가능 |
| **재생성 가능한 바이너리** | `benchmark_graphs_*/*.png` | 스크립트로 재생성 → 바이너리 추적 불필요 |
| **개인 작업 노트** | `session_progress.md` | 코드가 아닌 Claude 세션 로그, Obsidian에서 관리 |
| **대용량 로그** | `uart_*.log` | 재측정으로 재생성 가능, 수십 MB 누적 위험 |
| **빌드 산출물** | `*.elf`, `*.o`, `build/` | 항상 제외 |
| **Python 캐시** | `__pycache__/`, `*.pyc` | 자동 생성 |

### 새 파일 추가 전 체크리스트

```bash
# 1. 추가하려는 파일이 .gitignore에 해당하는지 확인
git check-ignore -v <파일경로>

# 2. 현재 .gitignore가 의도대로 작동하는지 확인
git status --short          # ?? 로 표시되면 무시됨 (tracked 아님)
git ls-files --others --ignored --exclude-standard  # 무시된 파일 전체 목록

# 3. 실수로 추적된 파일 발견 시 즉시 언트랙
git rm --cached <파일경로>   # 로컬 파일은 유지, 인덱스에서만 제거
echo "<패턴>" >> .gitignore
git commit -m "chore: untrack <파일명> + update .gitignore"
```

### 새 산출물 타입 발생 시

새로운 종류의 파일(새 확장자, 새 디렉토리)이 생기면 PR 생성 **전에**:

1. 해당 파일이 재생성 가능한지 판단
2. 재생성 가능 → `.gitignore`에 패턴 추가
3. 재생성 불가 (실험 데이터, 논문 근거) → 추적 유지, PR 본문에 명시

---

## 표준 워크플로 (이슈 → PR → 머지)

### 1. Issue 먼저 생성

```bash
gh issue create --title "feat: 작업 제목" --body "배경 및 목표"
# → #N 번호 부여
```

### 2. 브랜치 생성

```bash
git checkout main
git pull --ff-only origin main
git checkout -b feat/#N-slug
```

### 3. 작업 & 커밋 (PR 사이즈 가이드라인 준수)

```bash
git add <변경 파일>   # -A 또는 . 사용 금지 (로그 파일 오염 방지)
git commit -m "feat(scope): 설명 (#N)"
```

**PR 사이즈 가이드라인**:

| 변경 종류 | 별도 PR |
|-----------|---------|
| 코드 변경 (`*.c`, `*.h`, `*.py`) | 메인 PR |
| 벤치마크 결과 (`*.txt`, `uart_*.log`) | 별도 PR 또는 메인 PR body에 파일 링크 |
| 그래프·이미지 (`*.png`) | 별도 PR (또는 results PR에 포함) |
| 문서 (`*.md`) | 코드 PR에 포함 허용 (소량일 경우) |

> 한 PR의 코드 변경이 **+500/-500 라인을 초과**하면 분할을 검토.  
> `uart_*.log` 파일은 `.gitignore`에 추가 권장.

### 4. 푸시 + PR 생성

```bash
git push -u origin feat/#N-slug

gh pr create \
  --base main \
  --title "feat(scope): 설명 (#N)" \
  --body "$(cat <<'EOF'
## 요약
- 변경 요지 1~3줄

## 검증
- [ ] cmake --build build/Debug 성공
- [ ] Flash + UART 로그 정상 부팅 확인
- [ ] 해당 시나리오 errors=0 (측정 평균 ms 명시)
- [ ] 기존 시나리오 regression 없음

Closes #N
EOF
)"
```

### 5. Squash merge

```bash
gh pr merge --squash --delete-branch
# GitHub Settings에서 squash-only로 강제 → UI에서도 squash만 표시됨
```

### 6. 로컬 정리 (머지 직후 반드시 실행)

```bash
git checkout main
git pull --ff-only origin main
git branch -d feat/#N-slug        # --delete-branch로 원격은 이미 삭제됨
git remote prune origin           # 혹시 남은 추적 브랜치 정리
```

---

## 멀티에이전트 Worktree 정리 정책

Claude Code 멀티에이전트(cmux teammate)가 worktree를 생성한 경우, 작업 완료 후 반드시 정리:

```bash
# 1. 잔여 변경 확인
git worktree list
git -C <worktree-path> status

# 2. 보존할 내용 있으면 별도 브랜치로 추출
git -C <worktree-path> checkout -b feat/#N-extracted

# 3. 불필요하면 제거
git worktree unlock <worktree-path>
git worktree remove <worktree-path> --force
git branch -D worktree-agent-<hash>
```

> worktree 브랜치(`worktree-agent-*`)는 **4일 이상 방치 금지**.  
> 세션 시작 시 `git worktree list`로 잠긴 worktree 유무 확인.

---

## 마일스톤 & 태그 정책

주요 단계 완료 시 태그로 고정 (재현 가능성 보장):

```bash
# Stage 완료 태그
git tag -a stage/7-cert-kem-matrix -m "Stage 7: 77/78 시나리오 n=100 완료"
git push origin stage/7-cert-kem-matrix

# 실험 브랜치 아카이브 (삭제 전 보존)
git tag archived/experiment-<slug> <SHA>
git push origin archived/experiment-<slug>
git branch -D experiment/<slug>
git push origin --delete experiment/<slug>
```

권장 태그 목록 (소급 적용 예정):

| 태그 | 커밋 | 의미 |
|------|------|------|
| `stage/1-ecdsa-baseline` | `cb99573` | ECDSA TLS 1.3 최초 동작 |
| `stage/4-falcon-hardfault-fix` | `5093bbf` | Falcon HardFault 수정 + 26/26 완료 |
| `stage/7-cert-kem-matrix` | `cdb56d1` | 77/78 cert×KEM 매트릭스 완료 |

---

## 정기 위생 체크리스트 (PR merge 후마다)

```bash
git branch --merged main        # → 빈 목록이어야 함 (feat/#25-instrumentation 현재 작업 제외)
git worktree list               # → 메인 worktree 하나만
git remote prune origin --dry-run  # → 정리할 것 없어야 함
```

---

## 실험(`experiment/*`) 브랜치 운영

- `main`에 **merge하지 않을 수도** 있음
- 성공한 조각만 `feat/#N-slug`로 재정리해 별도 PR
- 방치 기한: **30일**. 초과 시 archived 태그 후 삭제

---

## 되돌리기 정책

- `main` 커밋 되돌리기 전에 이슈 생성 후 `git revert <SHA>` 사용
- `reset --hard` · `force-push`는 `main`에 금지
- 이미 push된 브랜치 history rewrite 금지

---

## PR 체크리스트 (템플릿)

```markdown
## 요약
- 변경 요지 1~3줄

## 검증
- [ ] cmake --build build/Debug 성공
- [ ] Flash + UART 로그 정상 부팅 확인
- [ ] 해당 시나리오 errors=0 (평균 ms 명시)
- [ ] 기존 시나리오 regression 없음

## 사이즈 체크
- [ ] 코드 변경 ≤ 500 라인 (초과 시 분할 검토)
- [ ] uart_*.log / *.png 파일이 이 PR에 포함되지 않음

Closes #N
```
