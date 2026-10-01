try { require('dotenv').config(); } catch (e) {}
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());


// 환경 변수 설정 (기본 Fallback 제공 및 /rest/v1 등 추가 경로 자동 제거)
let rawSupabaseUrl = (process.env.SUPABASE_URL || 'https://gylnpuzwwiezrxyrpydh.supabase.co').trim();
try {
  const parsed = new URL(rawSupabaseUrl);
  rawSupabaseUrl = parsed.origin;
} catch (e) {
  rawSupabaseUrl = rawSupabaseUrl.replace(/\/rest\/v1\/?$/, '').replace(/\/+$/, '');
}
const SUPABASE_URL = rawSupabaseUrl;
const SUPABASE_KEY = (process.env.SUPABASE_ANON_KEY || 'sb_publishable_vRJKHAuJQcgH7SOlo1MMyQ_4egYXQPX').trim().replace(/^["']|["']$/g, '');
const JWT_SECRET = (process.env.JWT_SECRET || 'skt-k-digital-task7-secret').trim().replace(/^["']|["']$/g, '');

// Supabase 클라이언트 안전 생성 (서버 런타임 오류 방어)
let supabase = null;
if (SUPABASE_URL && SUPABASE_KEY) {
  try {
    supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
  } catch (err) {
    console.error('Supabase 클라이언트 생성 실패:', err.message);
  }
}

// [미들웨어] 토큰 검증 및 인가
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: '로그인이 필요합니다.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: '유효하지 않거나 만료된 토큰입니다.' });
    req.user = user;
    next();
  });
}

// [진단용 엔드포인트] 브라우저에서 /api/status 접속 시 Supabase 연결 및 환경변수 상태 확인
app.get(['/api/status', '/status', '/api/health'], async (req, res) => {
  let dbConnection = 'disconnected';
  let dbError = null;

  if (supabase) {
    try {
      const { error } = await supabase.from('users').select('id', { head: true, count: 'exact' });
      if (error) {
        dbConnection = 'failed';
        dbError = error.message;
      } else {
        dbConnection = 'connected';
      }
    } catch (e) {
      dbConnection = 'error';
      dbError = e.message;
    }
  }

  res.json({
    status: 'ok',
    supabaseUrl: SUPABASE_URL,
    hasAnonKey: !!SUPABASE_KEY,
    dbConnection,
    dbError,
    hint: dbError ? 'Supabase 대시보드(Settings > API)에서 발급받은 anon key를 환경변수(SUPABASE_ANON_KEY)로 등록하세요.' : '정상 동작 중'
  });
});

// 1. 회원가입 (경로 매칭 오류 원천 차단형)
app.post(['/api/auth/signup', '/auth/signup', '/signup'], async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: '이메일과 비밀번호를 입력하세요.' });

  if (!supabase) {
    return res.status(500).json({ error: 'Supabase 연동 정보(URL/KEY)가 올바르게 설정되지 않았습니다.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const { data, error } = await supabase
      .from('users')
      .insert([{ id: 'user_' + Date.now(), email, password: hashedPassword }]);

    if (error) {
      if (error.code === '23505') {
        return res.status(409).json({ error: '이미 등록된 이메일 계정입니다.' });
      }
      if (error.code === 'PGRST205' || (error.message && error.message.includes('schema cache'))) {
        return res.status(500).json({ error: "Supabase DB에 'users' 테이블이 없습니다. Supabase 대시보드에서 'users' 테이블을 생성해주세요." });
      }
      if (error.code === '42501') {
        return res.status(403).json({ error: "Supabase 'users' 테이블의 RLS 보안 정책으로 인해 저장이 거부되었습니다." });
      }
      throw error;
    }
    res.status(201).json({ message: '회원가입 성공' });
  } catch (err) {
    res.status(500).json({ error: err.message || '회원가입 처리 중 오류 발생' });
  }
});

// 2. 로그인
app.post(['/api/auth/login', '/auth/login', '/login'], async (req, res) => {
  const { email, password } = req.body;

  if (!supabase) {
    return res.status(500).json({ error: 'Supabase 연동 정보(URL/KEY)가 올바르게 설정되지 않았습니다.' });
  }

  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (error) {
      if (error.code === 'PGRST116') {
        return res.status(401).json({ error: '존재하지 않는 사용자입니다.' });
      }
      if (error.code === 'PGRST205' || (error.message && error.message.includes('schema cache'))) {
        return res.status(500).json({ error: "Supabase DB에 'users' 테이블이 없습니다." });
      }
      return res.status(401).json({ error: '존재하지 않는 사용자이거나 조회에 실패했습니다.' });
    }

    if (!user) return res.status(401).json({ error: '존재하지 않는 사용자입니다.' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: '비밀번호가 일치하지 않습니다.' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message || '로그인 처리 중 오류 발생' });
  }
});

// 3. 태스크 목록 조회
app.get(['/api/todos', '/todos'], authenticateToken, async (req, res) => {
  if (!supabase) {
    return res.status(500).json({ error: 'Supabase 연동 정보(URL/KEY)가 올바르게 설정되지 않았습니다.' });
  }

  try {
    const { data, error } = await supabase.from('todos').select('*').eq('user_id', req.user.email);
    if (error) {
      if (error.code === 'PGRST205') {
        return res.status(500).json({ error: "Supabase DB에 'todos' 테이블이 없습니다." });
      }
      throw error;
    }
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. 태스크 추가
app.post(['/api/todos', '/todos'], authenticateToken, async (req, res) => {
  if (!supabase) {
    return res.status(500).json({ error: 'Supabase 연동 정보(URL/KEY)가 올바르게 설정되지 않았습니다.' });
  }

  const { title, dueDate, due_date, priority, tag, estTime, est_time } = req.body;
  try {
    const newTodo = {
      user_id: req.user.email,
      title,
      due_date: due_date || dueDate,
      priority: priority || '보통',
      tag: tag || '일반',
      est_time: est_time || estTime || 60
    };
    const { data, error } = await supabase.from('todos').insert([newTodo]).select();
    if (error) throw error;
    res.status(201).json(data ? data[0] : newTodo);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5. 태스크 삭제
app.delete(['/api/todos/:id', '/todos/:id'], authenticateToken, async (req, res) => {
  if (!supabase) {
    return res.status(500).json({ error: 'Supabase 연동 정보(URL/KEY)가 올바르게 설정되지 않았습니다.' });
  }

  const { id } = req.params;
  try {
    const { error } = await supabase.from('todos').delete().eq('id', id).eq('user_id', req.user.email);
    if (error) throw error;
    res.json({ message: '삭제 성공' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = app;