# Defense by Hack

AI 기반 웹 어플리케이션 취약점 분석 및 공격 시뮬레이터

## 기능

- **취약점 분석**: 코드를 붙여넣으면 Claude AI가 OWASP Top 10 기반으로 취약점을 실시간 스트리밍으로 분석
- **코드 수정 제안**: 발견된 취약점별 before/after 코드 수정 예시 제공
- **공격 시뮬레이션**: 각 취약점이 실제로 어떻게 악용될 수 있는지 단계별 교육용 시뮬레이션
- **리포트 내보내기**: 분석 결과를 JSON 또는 HTML 리포트로 다운로드

## 지원 언어

JavaScript, TypeScript, Python, PHP, Java, HTML, CSS

## 설치 및 실행

### 1. 환경 변수 설정
```bash
cp .env.example .env
# .env 파일을 열고 ANTHROPIC_API_KEY 설정
```

### 2. Docker Compose로 실행 (권장)
```bash
docker-compose up --build
```
- 프론트엔드: http://localhost:3000
- 백엔드 API: http://localhost:8000

### 3. 개발 서버로 실행

**Backend (FastAPI)**
```bash
cd backend
pip install -r requirements.txt
ANTHROPIC_API_KEY=your_key uvicorn main:app --reload --port 8000
```

**Frontend (Next.js)**
```bash
cd frontend
npm install
npm run dev
```

## 기술 스택

- **Frontend**: Next.js 14 (App Router), TypeScript, Tailwind CSS, CodeMirror 6
- **Backend**: FastAPI (Python 3.11), Anthropic SDK
- **AI**: Claude claude-sonnet-4-6 with SSE streaming
- **배포**: Docker Compose

## 주의사항

이 도구는 교육 목적으로 제작되었습니다. 공격 시뮬레이션 기능은 취약점 이해 및 방어를 위한 학습 목적으로만 사용하세요.
