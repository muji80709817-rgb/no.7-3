const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());

// 보안 원칙에 따라 환경변수(process.env)로만 키를 가져옵니다.
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// [미들웨어] 토큰 검증 및 인가
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

// 1. 회원가입
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: '이메일과 비밀번호를 입력하세요.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const { data, error } = await supabase
      .from('users')
      .insert([{ 
        id: 'user_' + Date.now(), 
        email, 
        password: hashedPassword 
      }]);

    if (error) throw error;
    res.status(201).json({ message: '회원가입 성공' });
  } catch (err) {
    res.status(500).json({ error: err.message || '회원가입 처리 중 오류 발생' });
  }
});

// 2. 로그인
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: '존재하지 않는 사용자입니다.' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: '비밀번호가 일치하지 않습니다.' });
    }

    // JWT 토큰 발급
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: '로그인 처리 중 오류 발생' });
  }
});

// 3. 태스크 목록 조회
app.get('/api/todos', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('todos')
      .select('*')
      .eq('user_id', req.user.email);

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. 태스크 추가
app.post('/api/todos', authenticateToken, async (req, res) => {
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

    const { data, error } = await supabase
      .from('todos')
      .insert([newTodo])
      .select();

    if (error) throw error;
    res.status(201).json(data ? data[0] : newTodo);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5. 태스크 삭제
app.delete('/api/todos/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const { error } = await supabase
      .from('todos')
      .delete()
      .eq('id', id)
      .eq('user_id', req.user.email);

    if (error) throw error;
    res.json({ message: '삭제 성공' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = app;