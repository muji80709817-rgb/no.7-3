const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());

// 전달받으신 Supabase URL 및 API Key 적용
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://gylnpuzwwiezrxyrpydh.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY || 'sb_publishable_vRJKHAuJQcgH7SOlo1MMyQ_4egYXQPX';
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// JWT 비밀키
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-pds-task7-key';

// [미들웨어] 토큰 검증 및 인가 (401 / 403 처리)
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: '로그인이 필요합니다.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: '유효하지 않거나 만료된 토큰입니다.' });
    }
    req.user = user;
    next();
  });
}

// 1. 회원가입 (Supabase DB 저장)
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: '이메일과 비밀번호를 모두 입력해 주세요.' });
    }

    // 중복 아이디 DB 확인
    const { data: existingUser } = await supabase
      .from('users')
      .select('email')
      .eq('email', email)
      .maybeSingle();

    if (existingUser) {
      return res.status(400).json({ error: '이미 존재하는 계정입니다.' });
    }

    // 비밀번호 해싱 후 DB 저장
    const hashedPassword = await bcrypt.hash(password, 12);
    const userId = `user_${Date.now()}`;

    const { error } = await supabase
      .from('users')
      .insert([{ id: userId, email, password: hashedPassword }]);

    if (error) {
      return res.status(500).json({ error: 'DB 저장 실패: ' + error.message });
    }

    return res.status(201).json({ message: '회원가입 완료', userId });
  } catch (err) {
    return res.status(500).json({ error: '회원가입 처리 중 서버 오류가 발생했습니다.' });
  }
});

// 2. 로그인 (Supabase DB 조회 및 JWT 발급)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .maybeSingle();

    if (error || !user) {
      return res.status(401).json({ error: '이메일 또는 비밀번호가 일치하지 않습니다.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: '이메일 또는 비밀번호가 일치하지 않습니다.' });
    }

    // JWT 토큰 발급 (유효기간 7일)
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      message: '로그인 성공',
      token,
      user: { id: user.id, email: user.email }
    });
  } catch (err) {
    return res.status(500).json({ error: '로그인 처리 중 서버 오류가 발생했습니다.' });
  }
});

// 3. 내 자료 목록 조회 (DB에서 해당 유저 데이터만 추출)
app.get('/api/todos', authenticateToken, async (req, res) => {
  try {
    const { data: myTodos, error } = await supabase
      .from('todos')
      .select('*')
      .eq('user_id', req.user.userId)
      .order('id', { ascending: false });

    if (error) {
      return res.status(500).json({ error: '데이터 조회 실패: ' + error.message });
    }

    const formattedTodos = (myTodos || []).map(t => ({
      id: t.id,
      userId: t.user_id,
      title: t.title,
      dueDate: t.due_date,
      priority: t.priority,
      tag: t.tag,
      estTime: t.est_time,
      completed: t.completed
    }));

    return res.json(formattedTodos);
  } catch (err) {
    return res.status(500).json({ error: '서버 오류' });
  }
});

// 4. 내 자료 작성 (DB Insert)
app.post('/api/todos', authenticateToken, async (req, res) => {
  try {
    const newTodo = {
      id: Date.now(),
      user_id: req.user.userId,
      title: req.body.title,
      due_date: req.body.dueDate || new Date().toISOString().split('T')[0],
      priority: req.body.priority || '보통',
      tag: req.body.tag || '기본',
      est_time: Number(req.body.estTime) || 60,
      completed: false
    };

    const { error } = await supabase.from('todos').insert([newTodo]);

    if (error) {
      return res.status(500).json({ error: 'DB 저장 실패: ' + error.message });
    }

    return res.status(201).json(newTodo);
  } catch (err) {
    return res.status(500).json({ error: '서버 오류' });
  }
});

// 5. 내 자료 삭제 (DB Delete)
app.delete('/api/todos/:id', authenticateToken, async (req, res) => {
  try {
    const todoId = Number(req.params.id);

    const { error } = await supabase
      .from('todos')
      .delete()
      .eq('id', todoId)
      .eq('user_id', req.user.userId);

    if (error) {
      return res.status(500).json({ error: '삭제 실패: ' + error.message });
    }

    return res.json({ message: '삭제 완료' });
  } catch (err) {
    return res.status(500).json({ error: '서버 오류' });
  }
});

module.exports = app;