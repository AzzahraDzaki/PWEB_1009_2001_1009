const fs = require('fs');
const express = require('express')
const mysql = require('mysql2')
const expressLayouts = require('express-ejs-layouts');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const path = require("path");
const moment = require('moment');
const multer = require('multer');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');

const app = express()
const port = 3000

//buat folder penampung file jika tidak ada
if (!fs.existsSync('./uploads')) {
  fs.mkdirSync('./uploads');
}

// Create multer storage configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

// Create multer upload configuration
const upload = multer({ storage: storage });



// middleware untuk parsing request body
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

app.set('views', path.join(__dirname, '/views'));

app.use('/css', express.static(path.resolve(__dirname, "public/css")));
app.use('/img', express.static(path.resolve(__dirname, "public/img")));


// template engine
app.set('view engine', 'ejs')

// layout ejs
app.use(expressLayouts);

// mengatur folder views
app.set('views', './views');

const saltRounds = 10;

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  database: 'db_pweb_fix'
});

db.connect((err)=>{
  if(err) throw err
 console.log('Database konek!')
//  const sql = "SELECT * FROM users";
//     db.query(sql,(err,result)=>{
//       console.log(result)
//     })
 })



// GET
//register Page
app.get('/register', function (req, res) {
  res.render('register',{
    title:'register',
    layout:'layouts/auth-layout'
  });
})

//register Page
app.get('/login', function (req, res) {
  res.render('login',{
    title:'login',
    layout:'layouts/auth-layout'
  });
})

// logout
app.get('/logout', function(req, res) {
  res.clearCookie('token');
  res.redirect('/login');
});

function requireAuth(req, res, next) {
  
  const token = req.cookies.token;

  if (!token) {
    res.redirect('/login');
    return;
  }
  

  jwt.verify(token, 'secret_key', function(err, decoded) {
    if (err) {
      res.redirect('/login');
      return;
    }

    req.user_id = decoded.user_id;
    next();
  });
}


//index Page
app.get('/',requireAuth, function (req, res) {
  res.render('index',{
    title:'Home',
    layout:'layouts/main-layout'
  });
})

//account Page
app.get('/account', requireAuth, function (req, res) {
  let user_id = req.user_id;
    const selectSql = `SELECT * FROM users WHERE user_id = ${user_id}`;
    db.query(selectSql, (err,result)=>{
      if (err) throw err;
      // Periksa apakah user sudah login dan aktif
      if (result[0].active === 0) {
        res.render('account',{
          user: result[0],
          title:'account',
          layout:'layouts/main-layout',
        });
      } else {
        // Jika user tidak aktif, arahkan kembali ke halaman login
        res.redirect('/login');
      }
    });
})

//forms Page
app.get('/forms', requireAuth, function (req, res) {

  const selectSql = `SELECT *
  FROM forms, users
  WHERE forms.user_id = users.user_id;
  `;
  db.query(selectSql, (err, result) => {
    if (err) {
      throw err;
    }
    res.render('forms', {// Assuming there's only one user with the given user_id
      forms: result,
      moment: moment,
      title: 'Forms',
      layout: 'layouts/main-layout'
    });
  });
})



//recent Page
app.get('/recent', requireAuth, function (req, res) {
  const user_id = req.user_id;

  // Get user information
  const selectUserSql = `SELECT * FROM users WHERE user_id = ${user_id}`;
  db.query(selectUserSql, (err, userResult) => {
    if (err) {
      throw err;
    }

    // Get recent submissions
    const selectSubmissionsSql = `SELECT *
      FROM submissions
      WHERE user_id = ${user_id}`;
    db.query(selectSubmissionsSql, (err, submissionResult) => {
      if (err) {
        throw err;
      }
      res.render('recent', {
        user: userResult[0],
        forms: submissionResult,
        moment: moment,
        title: 'Recent',
        layout: 'layouts/main-layout'
      });
    });
  });
});


//settings Page
app.get('/settings', function (req, res) {
  res.render('settings',{
    title:'settings',
    layout:'layouts/main-layout'
  });
})

//make form Page
app.get('/make-form', function (req, res) {
  res.render('make-form',{
    title:'make form',
    layout:'layouts/main-layout'
  });
})

app.get('/submission/:form_id', requireAuth, function(req, res) {
  const user_id = req.user_id;
  const form_id = req.params.form_id;

  // check if user is the creator of the form
  const formSql = 'SELECT * FROM forms WHERE form_id = ?';
  db.query(formSql, [form_id], function (err, formResult) {
    if (err) throw err;

    const formCreator = formResult[0].user_id;
    if (user_id === formCreator) {
      res.send('Upss!! Anda tidak bisa submit form sendiri yaa');
      return;
    }

    // check if user has submitted the form
    const submissionSql =
      'SELECT * FROM submissions WHERE form_id = ? AND user_id = ?';
    db.query(submissionSql, [form_id, user_id], function (
      err,
      submissionResult
    ) {
      if (err) throw err;

      let isSubmitted = false;
      let submission = null;

      if (submissionResult.length > 0) {
        isSubmitted = true;
        submission = submissionResult[0];
      }

      const selectUserSql = `SELECT * FROM users WHERE user_id = ${user_id}`;

      db.query(selectUserSql, function (err, userResult) {
        if (err) throw err;

        res.render('submission', {
          user: userResult[0],
          form: formResult[0],
          moment: moment,
          title: 'Submission',
          layout: 'layouts/main-layout',
          isSubmitted: isSubmitted,
          submission: submission
        });
      });
    });
  });
});

//responde
app.get('/respondents/:form_id', requireAuth, function (req, res) {
  const form_id = req.params.form_id;

  // Get all respondents for the specified form
  const selectRespondentsSql = `SELECT users.*
    FROM users
    INNER JOIN submissions ON users.user_id = submissions.user_id
    WHERE submissions.form_id = ?`;
  db.query(selectRespondentsSql, [form_id], (err, result) => {
    if (err) {
      throw err;
    }
    res.render('respondents', {
      respondents: result,
      moment:moment,
      title: 'Respondents',
      layout: 'layouts/main-layout'
    });
  });
});

app.get('/detail-respondent/:user_id', requireAuth, function (req, res) {
  const user_id = req.params.user_id;

  const user = `SELECT *
  FROM users
  JOIN submissions ON users.user_id = submissions.user_id
  WHERE users.user_id = ${user_id};
  `;
  db.query(user, [user_id], (err, result) => {
    if (err) {
      throw err;
    }
    res.render('detail-respondent', {
      respondent: result[0],
      moment:moment,
      title: 'Detail Respondents',
      layout: 'layouts/main-layout'
    });
  });
});


//download file pada detail pengumuman
app.get('/download/:user_id/:form_id', requireAuth, (req, res) => {
  const userId = req.params.user_id;
  const formId = req.params.form_id;

  // check if user has access to the form
  const formSql = 'SELECT * FROM forms WHERE form_id = ?';
  db.query(formSql, [formId], function(err, formResult) {
    if (err) throw err;
    if (formResult.length === 0) {
      console.log({msg:"404: form not found", err})
      return;
    }

    // check if submission exists
    const submissionSql = 'SELECT * FROM submissions WHERE user_id = ? AND form_id = ?';
    db.query(submissionSql, [userId, formId], function(err, submissionResult) {
      if (err) throw err;
      if (submissionResult.length === 0) {
        console.log({msg:"404: submission not found", err})
        return;
      }

      const submission = submissionResult[0];
      const filePath = `uploads/${submission.uploaded_file}`;

      res.download(filePath, submission.file_name, function(err) {
        if (err) {
          console.log({msg:"error", err});
          res.status(500).send('Internal server error');
        }
      });
    });
  });
});




//POST
app.post('/login', function (req, res) {
  const { usernameOrEmail, password } = req.body;

  const sql = 'SELECT * FROM users WHERE username = ? OR email = ?';
  db.query(sql, [usernameOrEmail, usernameOrEmail], function(err, result) {
    if (err) throw err;

    if (result.length === 0) {
      res.status(401).send('Username or password is incorrect!');
      return;
    }

    const user = result[0];

    // compare password
    bcrypt.compare(password, user.password, function(err, isValid) {
      if (err) throw err;

      if (!isValid) {
        res.status(401).send('Username or password is incorrect!');
        return;
      }

      // generate token
      const token = jwt.sign({ user_id: user.user_id }, 'secret_key');
      res.cookie('token', token, { httpOnly: true });

      res.redirect('/');
    });
  });
});


//register
app.post('/register', function (req, res) {
  const { email, username, password, confirm_password } = req.body;
  
  if (password !== confirm_password) {
    // Passwords do not match, send error response
    return res.status(400).send('Konfirmasi password tidak cocok!');
  }
  
  // check if username or email already exists
  const sqlCheck = 'SELECT * FROM users WHERE username = ? OR email = ?';
  db.query(sqlCheck, [username, email], (err, result) => {
    if (err) throw err;

    if (result.length > 0) {
      // username or email already exists, send error response
      return res.status(400).send('Username atau email sudah terdaftar');
    }

    // hash password
    bcrypt.hash(password, saltRounds, function(err, hash) {
      if (err) throw err;

      // insert user to database
      const sqlInsert = 'INSERT INTO users (email, username, password) VALUES (?, ?, ?)';
      const values = [email, username, hash];
      db.query(sqlInsert, values, (err, result) => {
        if (err) throw err;
        console.log('user terdaftar');
        res.redirect('/login');
      });
    });
  });
});

//edit profil
app.post('/edit-account', upload.single('avatar'), requireAuth, (req, res) => {
  let user_id = req.user_id;
  const { username, email, noHp } = req.body;
  let avatar = null;

  if (req.file) {
    avatar = req.file.filename;

    // Copy file to img directory
    const source = path.join(__dirname, 'uploads', avatar);
    const destination = path.join(__dirname, 'public', 'img', avatar);
    fs.copyFileSync(source, destination);
  }

  // Retrieve current avatar from database
  const selectUserSql = `SELECT avatar FROM users WHERE user_id = ${user_id}`;
  db.query(selectUserSql, (err, result) => {
    if (err) {
      throw err;
    }

    if (!avatar) {
      avatar = result[0].avatar;
    }

    // Insert data to MySQL
    const updateUserSql = `UPDATE users SET username=?, email=?, noHp=?, avatar=? WHERE user_id=${user_id}`;
    const values = [username, email, noHp, avatar];
    db.query(updateUserSql, values, (err, result) => {
      if (err) {
        throw err;
      }
      console.log({ message: "Data inserted to MySQL!", values });

      res.redirect('/account');
    });
  });
});


//ganti password
app.post('/ganti-password', requireAuth, (req, res) => {
  const { password, newPassword } = req.body;
  const userId = req.user_id;

  // Check if current password matches with database
  const sql = 'SELECT password FROM users WHERE user_id = ?';
  db.query(sql, [userId], (err, result) => {
    if (err) {
      console.log({ message: 'Internal Server Error', err });
      
    }

    const hashedPassword = result[0].password;
    bcrypt.compare(password, hashedPassword, (error, isMatch) => {
      if (error) {
        console.log({ message: 'Internal Server Error', err });
      }

      if (isMatch) {
        // If current password matches, hash new password and update database
        bcrypt.hash(newPassword, saltRounds, (err, hashedNewPassword) => {
          if (err) {
            console.log({ message: 'Internal Server Error', err });
          }

          const updateSql = 'UPDATE users SET password = ? WHERE user_id = ?';
          const values = [hashedNewPassword, userId];
          db.query(updateSql, values , (err, result) => {
            if (err) {
              console.log({ message: 'Internal Server Error', err });
            }
            console.log({ message: 'Password berhasil diubah', values });
            res.redirect('/settings');
          });
        });
      } else {
        // If current password doesn't match, send error message
        console.log({ message: 'Invalid current password', err });
        res.redirect('/settings');
      }
    });
  });
});



// make form post
app.post('/make-form', requireAuth, function (req, res) {
  
  const user_id = req.user_id;
  const title = req.body.title;
  const description = req.body.description;

  const sql = 'INSERT INTO forms (user_id, title, description) VALUES (?, ?, ?)';
  const values = [user_id, title, description];
  db.query(sql, values, (err, result) => {
    if (err) {
      throw err;
    }
    console.log({ message: 'Form created', values });
    res.redirect('/forms');
  });
});


// Handle file upload
app.post('/submit', upload.single('uploaded_file'), requireAuth, (req, res) => {
  const { form_id,description } = req.body;
  const uploaded_file = req.file.filename;

  const user_id = req.user_id;

  // Check if user has already submitted for the form
  const submissionSql = `SELECT * FROM submissions WHERE user_id = ? AND form_id = ?`;
  const submissionValues = [user_id, form_id];
  db.query(submissionSql, submissionValues, (err, submissionResult) => {
    if (err) {
      throw err;
    }

    // Insert data to MySQL
    const insertSql = `INSERT INTO submissions (user_id, form_id, uploaded_file, description) VALUES (?, ?, ?, ?)`;
    const insertValues = [user_id, form_id, uploaded_file, description];
    db.query(insertSql, insertValues, (err, result) => {
      if (err) {
        throw err;
      }
      console.log({ message: 'Submission complete!', insertValues });
    res.redirect('/forms');
    });
  });
});





app.listen(port,()=>{
  console.log(`listening on port ${port}`)
})

