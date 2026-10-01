require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');

const { put, del } = require('@vercel/blob');

const {
  MONGO_URI,
  JWT_SECRET = 'change-me',
  ADMIN_EMAIL = '',
  ADMIN_PASSWORD = '',
  PORT = 3000,
  BLOB_READ_WRITE_TOKEN,
} = process.env;

const app = express();

app.use(cors());
app.use(express.json());

let mongoPromise;

// =====================================================
// DATABASE
// =====================================================

async function connectDB() {
  if (!mongoPromise) {
    mongoPromise = mongoose
      .connect(MONGO_URI, {
        serverSelectionTimeoutMS: 10000,
      })
      .then(async () => {
        await seedAdmin();
        console.log('MongoDB connected');
      })
      .catch((err) => {
        console.error(
          'MongoDB connect nahi hua:',
          err.message
        );

        mongoPromise = null;
        throw err;
      });
  }

  return mongoPromise;
}

// =====================================================
// ROOT
// =====================================================

app.get('/', (req, res) => {
  res.json({
    ok: true,
    service: 'Yousify API',
    message: 'Backend is running',
  });
});

// =====================================================
// DATABASE MIDDLEWARE
// =====================================================

app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (err) {
    res.status(500).json({
      error: 'Database connection failed',
      detail: err.message,
    });
  }
});

// =====================================================
// MULTER
// 25 MB AUDIO LIMIT
// =====================================================

const upload = multer({
  storage: multer.memoryStorage(),

  limits: {
    fileSize: 25 * 1024 * 1024,
  },
});

// =====================================================
// MODELS
// =====================================================

const { ObjectId } = mongoose.Schema.Types;

const User = mongoose.model(
  'User',
  new mongoose.Schema({
    name: String,

    email: {
      type: String,
      unique: true,
      lowercase: true,
    },

    hash: String,

    role: {
      type: String,
      default: 'user',
    },
  })
);

const Song = mongoose.model(
  'Song',
  new mongoose.Schema(
    {
      title: String,

      lyrics: {
        type: String,
        default: '',
      },

      audio: String,

      by: String,

      uid: ObjectId,

      byAdmin: Boolean,

      approved: Boolean,
    },
    {
      timestamps: true,
    }
  )
);

const Playlist = mongoose.model(
  'Playlist',
  new mongoose.Schema({
    name: String,

    ownerId: ObjectId,

    ownerName: String,

    isPublic: Boolean,

    songIds: [ObjectId],
  })
);

// =====================================================
// HELPERS
// =====================================================

const w = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const userJson = (u) => ({
  uid: u.id,
  name: u.name,
  role: u.role,
});

const songJson = (s) => ({
  id: s.id,
  title: s.title,
  lyrics: s.lyrics,
  audio: s.audio,
  by: s.by,
  uid: String(s.uid),
  byAdmin: !!s.byAdmin,
  approved: !!s.approved,
  createdAt: s.createdAt,
});

const plJson = (p) => ({
  id: p.id,
  name: p.name,
  ownerId: String(p.ownerId),
  ownerName: p.ownerName,
  isPublic: !!p.isPublic,
  count: p.songIds.length,
});

// =====================================================
// AUTH
// =====================================================

function auth(req, res, next) {
  try {
    const header =
      req.headers.authorization || '';

    const token = header.startsWith('Bearer ')
      ? header.substring(7)
      : '';

    req.user = jwt.verify(
      token,
      JWT_SECRET
    );

    next();
  } catch {
    res.status(401).json({
      error: 'Dobara login karein',
    });
  }
}

const adminOnly = (req, res, next) => {
  if (req.user.role === 'admin') {
    return next();
  }

  return res.status(403).json({
    error: 'Sirf admin',
  });
};

const sign = (u) =>
  jwt.sign(
    {
      id: u.id,
      role: u.role,
      name: u.name,
    },
    JWT_SECRET,
    {
      expiresIn: '60d',
    }
  );

// =====================================================
// AUTH - SIGNUP
// =====================================================

app.post(
  '/auth/signup',
  w(async (req, res) => {
    const {
      name,
      email,
      password,
    } = req.body;

    if (
      !name ||
      !email ||
      !password ||
      password.length < 6
    ) {
      return res.status(400).json({
        error:
          'Naam, email aur 6+ chars ka password dein',
      });
    }

    const normalizedEmail =
      email.toLowerCase();

    if (
      await User.findOne({
        email: normalizedEmail,
      })
    ) {
      return res.status(400).json({
        error:
          'Ye email pehle se registered hai',
      });
    }

    const role =
      ADMIN_EMAIL &&
      normalizedEmail ===
        ADMIN_EMAIL.toLowerCase()
        ? 'admin'
        : 'user';

    const u = await User.create({
      name,
      email: normalizedEmail,
      hash: await bcrypt.hash(
        password,
        10
      ),
      role,
    });

    res.json({
      token: sign(u),
      user: userJson(u),
    });
  })
);

// =====================================================
// AUTH - LOGIN
// =====================================================

app.post(
  '/auth/login',
  w(async (req, res) => {
    const u = await User.findOne({
      email: (
        req.body.email || ''
      ).toLowerCase(),
    });

    if (
      !u ||
      !(await bcrypt.compare(
        req.body.password || '',
        u.hash
      ))
    ) {
      return res.status(400).json({
        error:
          'Email ya password ghalat hai',
      });
    }

    res.json({
      token: sign(u),
      user: userJson(u),
    });
  })
);

// =====================================================
// ME
// =====================================================

app.get(
  '/me',
  auth,
  w(async (req, res) => {
    const u = await User.findById(
      req.user.id
    );

    if (!u) {
      return res.status(401).json({
        error: 'User nahi mila',
      });
    }

    res.json(userJson(u));
  })
);

// =====================================================
// SONGS - LIST
// =====================================================

app.get(
  '/songs',
  auth,
  w(async (req, res) => {
    const songs = await Song.find({
      $or: [
        {
          approved: true,
        },
        {
          uid: req.user.id,
        },
      ],
    }).sort({
      createdAt: -1,
    });

    res.json(
      songs.map(songJson)
    );
  })
);

// =====================================================
// SONG UPLOAD
// =====================================================

app.post(
  '/songs',
  auth,
  upload.single('audio'),
  w(async (req, res) => {
    if (
      !req.file ||
      !req.body.title
    ) {
      return res.status(400).json({
        error:
          'Naam aur audio zaroori hain',
      });
    }

    // Check Blob token
    if (!BLOB_READ_WRITE_TOKEN) {
      console.error(
        'BLOB_READ_WRITE_TOKEN missing'
      );

      return res.status(500).json({
        error:
          'BLOB_READ_WRITE_TOKEN Railway environment mein missing hai',
      });
    }

    const admin =
      req.user.role === 'admin';

    const ext =
      path.extname(
        req.file.originalname
      ) || '.m4a';

    const filename =
      `songs/${Date.now()}-${Math.round(
        Math.random() * 1e6
      )}${ext}`;

    console.log(
      '========================================'
    );

    console.log(
      'STARTING BLOB UPLOAD'
    );

    console.log(
      'FILE:',
      req.file.originalname
    );

    console.log(
      'SIZE:',
      req.file.size
    );

    console.log(
      'MIME:',
      req.file.mimetype
    );

    console.log(
      'FILENAME:',
      filename
    );

    console.log(
      '========================================'
    );

    // PUBLIC VERCEL BLOB
    const blob = await put(
      filename,
      req.file.buffer,
      {
        access: 'public',

        token:
          BLOB_READ_WRITE_TOKEN,

        contentType:
          req.file.mimetype ||
          'audio/mpeg',

        addRandomSuffix: true,
      }
    );

    console.log(
      '========================================'
    );

    console.log(
      'BLOB UPLOAD SUCCESS'
    );

    console.log(
      'BLOB URL:',
      blob.url
    );

    console.log(
      '========================================'
    );

    // Invalid URL protection
    if (
      !blob.url ||
      blob.url.includes(
        '.undefined.blob.vercel-storage.com'
      )
    ) {
      console.error(
        'INVALID BLOB URL:',
        blob.url
      );

      return res.status(500).json({
        error:
          'Vercel Blob ne invalid URL return kiya',
      });
    }

    const s = await Song.create({
      title: req.body.title,

      lyrics:
        req.body.lyrics || '',

      audio: blob.url,

      by: req.user.name,

      uid: req.user.id,

      byAdmin: admin,

      approved: admin,
    });

    console.log(
      'SONG SAVED:',
      s.id
    );

    console.log(
      'AUDIO URL SAVED:',
      s.audio
    );

    res.json(
      songJson(s)
    );
  })
);

// =====================================================
// PENDING SONGS
// =====================================================

app.get(
  '/songs/pending',
  auth,
  adminOnly,
  w(async (req, res) => {
    const songs =
      await Song.find({
        approved: false,
      }).sort({
        createdAt: -1,
      });

    res.json(
      songs.map(songJson)
    );
  })
);

// =====================================================
// AUDIO URL
// =====================================================

app.get(
  '/songs/:id/audio',
  auth,
  w(async (req, res) => {
    console.log(
      '========================================'
    );

    console.log(
      'AUDIO REQUEST:',
      req.params.id
    );

    console.log(
      'USER:',
      req.user?.id
    );

    console.log(
      '========================================'
    );

    const s =
      await Song.findById(
        req.params.id
      );

    if (!s) {
      return res.status(404).json({
        error: 'Song nahi mila',
      });
    }

    if (
      !s.approved &&
      req.user.role !== 'admin' &&
      String(s.uid) !==
        String(req.user.id)
    ) {
      return res.status(403).json({
        error: 'Ijazat nahi',
      });
    }

    if (!s.audio) {
      return res.status(500).json({
        error:
          'Audio file missing',
      });
    }

    console.log(
      'PUBLIC AUDIO URL:',
      s.audio
    );

    res.json({
      url: s.audio,
    });
  })
);

// =====================================================
// APPROVE SONG
// =====================================================

app.post(
  '/songs/:id/approve',
  auth,
  adminOnly,
  w(async (req, res) => {
    await Song.findByIdAndUpdate(
      req.params.id,
      {
        approved: true,
      }
    );

    res.json({
      ok: true,
    });
  })
);

// =====================================================
// DELETE SONG
// =====================================================

app.delete(
  '/songs/:id',
  auth,
  w(async (req, res) => {
    const s =
      await Song.findById(
        req.params.id
      );

    if (!s) {
      return res.json({
        ok: true,
      });
    }

    if (
      req.user.role !== 'admin' &&
      String(s.uid) !==
        String(req.user.id)
    ) {
      return res.status(403).json({
        error: 'Ijazat nahi',
      });
    }

    if (s.audio) {
      if (!BLOB_READ_WRITE_TOKEN) {
        return res.status(500).json({
          error:
            'BLOB_READ_WRITE_TOKEN Railway environment mein missing hai',
        });
      }

      await del(
        s.audio,
        {
          token:
            BLOB_READ_WRITE_TOKEN,
        }
      );
    }

    await Playlist.updateMany(
      {},
      {
        $pull: {
          songIds: s._id,
        },
      }
    );

    await s.deleteOne();

    res.json({
      ok: true,
    });
  })
);

// =====================================================
// PLAYLISTS
// =====================================================

app.get(
  '/playlists',
  auth,
  w(async (req, res) => {
    const mine =
      await Playlist.find({
        ownerId: req.user.id,
      });

    const pub =
      await Playlist.find({
        isPublic: true,
        ownerId: {
          $ne: req.user.id,
        },
      });

    res.json({
      mine: mine.map(plJson),
      public: pub.map(plJson),
    });
  })
);

// =====================================================
// CREATE PLAYLIST
// =====================================================

app.post(
  '/playlists',
  auth,
  w(async (req, res) => {
    if (!req.body.name) {
      return res.status(400).json({
        error: 'Naam likhein',
      });
    }

    const p =
      await Playlist.create({
        name: req.body.name,

        ownerId: req.user.id,

        ownerName:
          req.user.name,

        isPublic:
          req.user.role ===
          'admin',

        songIds:
          req.body.songId
            ? [req.body.songId]
            : [],
      });

    res.json(
      plJson(p)
    );
  })
);

// =====================================================
// GET PLAYLIST
// =====================================================

app.get(
  '/playlists/:id',
  auth,
  w(async (req, res) => {
    const p =
      await Playlist.findById(
        req.params.id
      );

    if (!p) {
      return res.status(404).json({
        error:
          'Playlist nahi mili',
      });
    }

    if (
      !p.isPublic &&
      String(p.ownerId) !==
        req.user.id &&
      req.user.role !==
        'admin'
    ) {
      return res.status(403).json({
        error:
          'Ijazat nahi',
      });
    }

    const songs =
      await Song.find({
        _id: {
          $in: p.songIds,
        },

        approved: true,
      });

    res.json({
      ...plJson(p),
      songs:
        songs.map(songJson),
    });
  })
);

// =====================================================
// PLAYLIST OWNER CHECK
// =====================================================

async function ownPlaylist(
  req,
  res
) {
  const p =
    await Playlist.findById(
      req.params.id
    );

  if (
    !p ||
    (
      String(p.ownerId) !==
        req.user.id &&
      req.user.role !==
        'admin'
    )
  ) {
    res.status(403).json({
      error:
        'Ijazat nahi',
    });

    return null;
  }

  return p;
}

// =====================================================
// ADD SONG TO PLAYLIST
// =====================================================

app.post(
  '/playlists/:id/songs',
  auth,
  w(async (req, res) => {
    const p =
      await ownPlaylist(
        req,
        res
      );

    if (!p) return;

    await Playlist.updateOne(
      {
        _id: p._id,
      },
      {
        $addToSet: {
          songIds:
            req.body.songId,
        },
      }
    );

    res.json({
      ok: true,
    });
  })
);

// =====================================================
// REMOVE SONG FROM PLAYLIST
// =====================================================

app.delete(
  '/playlists/:id/songs/:sid',
  auth,
  w(async (req, res) => {
    const p =
      await ownPlaylist(
        req,
        res
      );

    if (!p) return;

    await Playlist.updateOne(
      {
        _id: p._id,
      },
      {
        $pull: {
          songIds:
            req.params.sid,
        },
      }
    );

    res.json({
      ok: true,
    });
  })
);

// =====================================================
// DELETE PLAYLIST
// =====================================================

app.delete(
  '/playlists/:id',
  auth,
  w(async (req, res) => {
    const p =
      await ownPlaylist(
        req,
        res
      );

    if (!p) return;

    await p.deleteOne();

    res.json({
      ok: true,
    });
  })
);

// =====================================================
// ADMIN
// =====================================================

async function seedAdmin() {
  if (
    !ADMIN_EMAIL ||
    !ADMIN_PASSWORD
  ) {
    return;
  }

  await User.findOneAndUpdate(
    {
      email:
        ADMIN_EMAIL.toLowerCase(),
    },

    {
      $set: {
        hash:
          await bcrypt.hash(
            ADMIN_PASSWORD,
            10
          ),

        role: 'admin',
      },

      $setOnInsert: {
        name: 'Admin',
      },
    },

    {
      upsert: true,
    }
  );

  console.log(
    'Admin tayyar: ' +
      ADMIN_EMAIL
  );
}

// =====================================================
// MULTER + GLOBAL ERROR HANDLER
// IMPORTANT
// =====================================================

app.use(
  (
    err,
    req,
    res,
    next
  ) => {
    console.error(
      '========================================'
    );

    console.error(
      'SERVER ERROR:'
    );

    console.error(err);

    console.error(
      '========================================'
    );

    // File too large
    if (
      err instanceof
      multer.MulterError
    ) {
      if (
        err.code ===
        'LIMIT_FILE_SIZE'
      ) {
        return res
          .status(400)
          .json({
            error:
              'Audio file bohat bari hai. Maximum size 25 MB hai.',
          });
      }

      return res
        .status(400)
        .json({
          error:
            `Upload error: ${err.message}`,
        });
    }

    // Other errors
    return res
      .status(500)
      .json({
        error:
          err.message ||
          'Server error',
      });
  }
);

// =====================================================
// EXPORT
// =====================================================

module.exports = app;

// =====================================================
// LOCAL DEVELOPMENT
// =====================================================

if (
  require.main ===
  module
) {
  connectDB()
    .then(() => {
      app.listen(
        PORT,
        '0.0.0.0',
        () => {
          console.log(
            'Yousify API chal rahi hai: port ' +
              PORT
          );
        }
      );
    })
    .catch((err) => {
      console.error(
        'Server start nahi hua:',
        err
      );

      process.exit(1);
    });
}