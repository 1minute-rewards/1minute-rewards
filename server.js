const express = require('express');
const path = require('path');
const Database = require('better-sqlite3');
const crypto = require('crypto');

const app = express();

const PORT = process.env.PORT || 3000;

const DB_FILE =
  process.env.DB_FILE ||
  path.join(__dirname, 'rewards.db');

const db = new Database(DB_FILE);


/* ================= BASIC SETUP ================= */

app.use(express.json());

app.use(
  express.static(
    path.join(__dirname, 'public')
  )
);


/* ================= DATABASE ================= */

db.pragma('journal_mode = WAL');

db.exec(`

CREATE TABLE IF NOT EXISTS users(

 id INTEGER PRIMARY KEY AUTOINCREMENT,

 name TEXT NOT NULL,

 email TEXT UNIQUE NOT NULL,

 password_hash TEXT NOT NULL,

 points INTEGER NOT NULL DEFAULT 0,

 referral_code TEXT UNIQUE NOT NULL,

 referred_by TEXT,

 created_at TEXT NOT NULL
 DEFAULT CURRENT_TIMESTAMP

);


CREATE TABLE IF NOT EXISTS tasks(

 id INTEGER PRIMARY KEY AUTOINCREMENT,

 title TEXT NOT NULL,

 description TEXT NOT NULL DEFAULT '',

 reward INTEGER NOT NULL,

 active INTEGER NOT NULL DEFAULT 1,

 created_at TEXT NOT NULL
 DEFAULT CURRENT_TIMESTAMP

);


CREATE TABLE IF NOT EXISTS completions(

 id INTEGER PRIMARY KEY AUTOINCREMENT,

 user_id INTEGER NOT NULL,

 task_id INTEGER NOT NULL,

 created_at TEXT NOT NULL
 DEFAULT CURRENT_TIMESTAMP,

 UNIQUE(user_id, task_id),

 FOREIGN KEY(user_id)
 REFERENCES users(id),

 FOREIGN KEY(task_id)
 REFERENCES tasks(id)

);


CREATE TABLE IF NOT EXISTS withdrawals(

 id INTEGER PRIMARY KEY AUTOINCREMENT,

 user_id INTEGER NOT NULL,

 amount INTEGER NOT NULL,

 method TEXT NOT NULL,

 account TEXT NOT NULL,

 status TEXT NOT NULL
 DEFAULT 'Pending',

 created_at TEXT NOT NULL
 DEFAULT CURRENT_TIMESTAMP,

 FOREIGN KEY(user_id)
 REFERENCES users(id)

);

`);


/* ================= DEFAULT TASKS ================= */

const taskCount =
  db
    .prepare(
      'SELECT COUNT(*) AS c FROM tasks'
    )
    .get().c;


if(taskCount === 0){

  const add =
    db.prepare(`

      INSERT INTO
      tasks(title,description,reward)

      VALUES(?,?,?)

    `);


  const defaultTasks = [

    [
      'Daily Check-in',
      'প্রতিদিন check-in করুন',
      10
    ],

    [
      'Quick Quiz',
      'ছোট quiz সম্পন্ন করুন',
      30
    ],

    [
      'Survey',
      'একটি short survey সম্পন্ন করুন',
      50
    ]

  ];


  for(
    const task of defaultTasks
  ){

    add.run(...task);

  }

}


/* ================= HELPERS ================= */

const hash = password =>

  crypto
    .createHash('sha256')
    .update(password)
    .digest('hex');


const createToken = () =>

  crypto
    .randomBytes(32)
    .toString('hex');


const createReferralCode = () =>

  '1MIN' +
  crypto
    .randomBytes(4)
    .toString('hex')
    .toUpperCase();


/* ================= SESSIONS ================= */

const sessions = new Map();


function auth(req,res,next){

  const header =
    req.headers.authorization || '';


  const token =
    header.startsWith('Bearer ')
      ? header.substring(7)
      : null;


  if(!token){

    return res
      .status(401)
      .json({
        error:'Login required'
      });

  }


  const userId =
    sessions.get(token);


  if(!userId){

    return res
      .status(401)
      .json({
        error:'Session expired. Please login again.'
      });

  }


  req.userId = userId;

  next();

}


/* ================= HOME API ================= */

app.get('/',(req,res)=>{

  res.sendFile(
    path.join(
      __dirname,
      'public',
      'index.html'
    )
  );

});


/* ================= REGISTER ================= */

app.post(
  '/api/register',
  (req,res)=>{

    const {
      name,
      email,
      password
    } = req.body || {};


    if(
      !name ||
      !email ||
      !password
    ){

      return res
        .status(400)
        .json({
          error:
            'Name, email and password required'
        });

    }


    if(
      password.length < 6
    ){

      return res
        .status(400)
        .json({
          error:
            'Password must be at least 6 characters'
        });

    }


    const cleanName =
      String(name).trim();


    const cleanEmail =
      String(email)
        .trim()
        .toLowerCase();


    if(
      !cleanName ||
      !cleanEmail
    ){

      return res
        .status(400)
        .json({
          error:
            'Name and email are required'
        });

    }


    try{

      let referralCode;


      /* Make sure referral code is unique */

      do{

        referralCode =
          createReferralCode();

      }while(

        db
          .prepare(
            'SELECT id FROM users WHERE referral_code=?'
          )
          .get(referralCode)

      );


      const info =
        db
          .prepare(`

            INSERT INTO users(

              name,
              email,
              password_hash,
              referral_code,
              referred_by

            )

            VALUES(?,?,?,?,?)

          `)
          .run(

            cleanName,

            cleanEmail,

            hash(password),

            referralCode,

            null

          );


      const token =
        createToken();


      sessions.set(
        token,
        Number(info.lastInsertRowid)
      );


      res.json({

        token,

        user:{

          id:
            Number(info.lastInsertRowid),

          name:
            cleanName,

          email:
            cleanEmail,

          points:0,

          referral_code:
            referralCode

        }

      });


    }catch(error){

      if(
        String(error.message)
          .includes('UNIQUE')
      ){

        return res
          .status(400)
          .json({
            error:
              'Email already registered'
          });

      }


      console.error(
        'REGISTER ERROR:',
        error
      );


      res
        .status(500)
        .json({
          error:
            'Registration failed'
        });

    }

  }
);


/* ================= LOGIN ================= */

app.post(
  '/api/login',
  (req,res)=>{

    const {
      email,
      password
    } = req.body || {};


    if(
      !email ||
      !password
    ){

      return res
        .status(400)
        .json({
          error:
            'Email and password required'
        });

    }


    const cleanEmail =
      String(email)
        .trim()
        .toLowerCase();


    const user =
      db
        .prepare(`

          SELECT *

          FROM users

          WHERE email=?

          AND password_hash=?

        `)
        .get(

          cleanEmail,

          hash(password)

        );


    if(!user){

      return res
        .status(401)
        .json({
          error:
            'Invalid email or password'
        });

    }


    const token =
      createToken();


    sessions.set(
      token,
      user.id
    );


    res.json({

      token,

      user:{

        id:user.id,

        name:user.name,

        email:user.email,

        points:user.points,

        referral_code:
          user.referral_code

      }

    });

  }
);


/* ================= CURRENT USER ================= */

app.get(
  '/api/me',
  auth,
  (req,res)=>{

    const user =
      db
        .prepare(`

          SELECT
            id,
            name,
            email,
            points,
            referral_code

          FROM users

          WHERE id=?

        `)
        .get(req.userId);


    if(!user){

      return res
        .status(404)
        .json({
          error:
            'User not found'
        });

    }


    res.json({
      user
    });

  }
);


/* ================= TASKS ================= */

app.get(
  '/api/tasks',
  auth,
  (req,res)=>{

    const tasks =
      db
        .prepare(`

          SELECT

            t.id,

            t.title,

            t.description,

            t.reward,

            t.active,

            EXISTS(

              SELECT 1

              FROM completions c

              WHERE
                c.task_id=t.id

              AND
                c.user_id=?

            ) AS completed

          FROM tasks t

          WHERE t.active=1

          ORDER BY t.id DESC

        `)
        .all(req.userId);


    res.json({
      tasks
    });

  }
);


/* ================= COMPLETE TASK ================= */

app.post(
  '/api/tasks/:id/complete',
  auth,
  (req,res)=>{

    const taskId =
      Number(req.params.id);


    if(
      !Number.isInteger(taskId)
    ){

      return res
        .status(400)
        .json({
          error:
            'Invalid task'
        });

    }


    const task =
      db
        .prepare(`

          SELECT *

          FROM tasks

          WHERE id=?

          AND active=1

        `)
        .get(taskId);


    if(!task){

      return res
        .status(404)
        .json({
          error:
            'Task not found'
        });

    }


    try{

      const transaction =
        db.transaction(()=>{

          db
            .prepare(`

              INSERT INTO
              completions(
                user_id,
                task_id
              )

              VALUES(?,?)

            `)
            .run(
              req.userId,
              taskId
            );


          db
            .prepare(`

              UPDATE users

              SET points =
                points + ?

              WHERE id=?

            `)
            .run(
              task.reward,
              req.userId
            );

        });


      transaction();


      const user =
        db
          .prepare(
            'SELECT points FROM users WHERE id=?'
          )
          .get(req.userId);


      res.json({

        success:true,

        points:
          user.points,

        reward:
          task.reward

      });


    }catch(error){

      if(
        String(error.message)
          .includes('UNIQUE')
      ){

        return res
          .status(409)
          .json({
            error:
              'Task already completed'
          });

      }


      console.error(
        'TASK ERROR:',
        error
      );


      res
        .status(500)
        .json({
          error:
            'Could not complete task'
        });

    }

  }
);


/* ================= WITHDRAWAL ================= */

app.post(
  '/api/withdrawals',
  auth,
  (req,res)=>{

    const {
      amount,
      method,
      account
    } = req.body || {};


    const points =
      Number(amount);


    if(
      !Number.isInteger(points) ||
      points < 100
    ){

      return res
        .status(400)
        .json({
          error:
            'Minimum withdrawal is 100 points'
        });

    }


    if(
      !method ||
      !account
    ){

      return res
        .status(400)
        .json({
          error:
            'Payment method and account required'
        });

    }


    const user =
      db
        .prepare(
          'SELECT points FROM users WHERE id=?'
        )
        .get(req.userId);


    if(!user){

      return res
        .status(404)
        .json({
          error:
            'User not found'
        });

    }


    if(
      user.points < points
    ){

      return res
        .status(400)
        .json({
          error:
            'Insufficient points'
        });

    }


    try{

      const transaction =
        db.transaction(()=>{

          db
            .prepare(`

              UPDATE users

              SET points =
                points - ?

              WHERE id=?

            `)
            .run(
              points,
              req.userId
            );


          db
            .prepare(`

              INSERT INTO withdrawals(

                user_id,
                amount,
                method,
                account

              )

              VALUES(?,?,?,?)

            `)
            .run(

              req.userId,

              points,

              String(method),

              String(account).trim()

            );

        });


      transaction();


      res.json({

        success:true,

        message:
          'Withdrawal request submitted'

      });


    }catch(error){

      console.error(
        'WITHDRAW ERROR:',
        error
      );


      res
        .status(500)
        .json({
          error:
            'Withdrawal request failed'
        });

    }

  }
);


/* ================= ADMIN TASKS ================= */

/*
  এগুলো এখন basic admin API।
  পরে Admin Panel বানিয়ে এগুলো ব্যবহার করা যাবে।
*/


app.get(
  '/api/admin/tasks',
  (req,res)=>{

    const tasks =
      db
        .prepare(
          'SELECT * FROM tasks ORDER BY id DESC'
        )
        .all();


    res.json({
      tasks
    });

  }
);


app.post(
  '/api/admin/tasks',
  (req,res)=>{

    const {
      title,
      description='',
      reward
    } = req.body || {};


    if(
      !title ||
      !Number.isInteger(reward) ||
      reward < 1
    ){

      return res
        .status(400)
        .json({
          error:
            'Invalid task'
        });

    }


    const result =
      db
        .prepare(`

          INSERT INTO tasks(
            title,
            description,
            reward
          )

          VALUES(?,?,?)

        `)
        .run(

          String(title).trim(),

          String(description),

          reward

        );


    res.json({

      success:true,

      id:
        Number(result.lastInsertRowid)

    });

  }
);


app.patch(
  '/api/admin/tasks/:id',
  (req,res)=>{

    const active =
      req.body &&
      req.body.active
        ? 1
        : 0;


    db
      .prepare(`

        UPDATE tasks

        SET active=?

        WHERE id=?

      `)
      .run(
        active,
        req.params.id
      );


    res.json({
      success:true
    });

  }
);


/* ================= ADMIN STATS ================= */

app.get(
  '/api/admin/stats',
  (req,res)=>{

    const users =
      db
        .prepare(
          'SELECT COUNT(*) AS c FROM users'
        )
        .get().c;


    const completed =
      db
        .prepare(
          'SELECT COUNT(*) AS c FROM completions'
        )
        .get().c;


    const points =
      db
        .prepare(
          'SELECT COALESCE(SUM(points),0) AS s FROM users'
        )
        .get().s;


    const pending =
      db
        .prepare(`

          SELECT COUNT(*) AS c

          FROM withdrawals

          WHERE status='Pending'

        `)
        .get().c;


    res.json({

      users,

      completed,

      points,

      pending

    });

  }
);


/* ================= HEALTH CHECK ================= */

app.get(
  '/health',
  (req,res)=>{

    res.json({

      status:'ok',

      service:'1Minute Rewards'

    });

  }
);


/* ================= ERROR HANDLER ================= */

app.use(
  (err,req,res,next)=>{

    console.error(err);


    res
      .status(500)
      .json({
        error:
          'Internal server error'
      });

  }
);


/* ================= START SERVER ================= */

app.listen(
  PORT,
  '0.0.0.0',
  ()=>{

    console.log(
      `1Minute Rewards running on port ${PORT}`
    );

  }
);
