const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());

// 환경변수 문제 원천 차단: 눈에 보이지 않는 공백을 .trim()으로 완벽히 제거합니다.
const SUPABASE_URL = 'https://gyinpuzwwiezrxyrpydh.supabase.co'.trim();
// ★ 아래 따옴표 안에 새로 발급받으신 anon key를 덮어쓰세요.
const SUPABASE_KEY = '여기에_새로_발급받은_anon_key_붙여넣기'.trim();
const JWT_SECRET = 'skt-k-digital-task7-secret'.trim();

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

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

app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: '이메일과 비밀번호를 입력하세요.' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const { data, error } = await supabase
      .from('users')
      .insert([{
        id: 'user_' + Date.now(), // Supabase users 테이블 구조에 맞춘 ID 자동 생성
        email,
        password: hashedPassword
      }]);

    if (error) throw error;
    res.status(201).json({ message: '회원가입 성공' });
  } catch (err) {
    res.status(500).json({ error: err.message || '가입 오류' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (error || !user) return res.status(401).json({ error: '존재하지 않는 사용자입니다.' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: '비밀번호가 일치하지 않습니다.' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/todos', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase.from('todos').select('*').eq('user_id', req.user.email);
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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
    const { data, error } = await supabase.from('todos').insert([newTodo]).select();
    if (error) throw error;
    res.status(201).json(data ? data[0] : newTodo);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/todos/:id', authenticateToken, async (req, res) => {
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