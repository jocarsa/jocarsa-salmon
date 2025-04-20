<?php
session_start();
date_default_timezone_set('UTC');

// SQLite database
$db = new SQLite3('../databases/salmon.db');

/**
 * CREATE / MIGRATE TABLES (if not exist)
 */
$db->exec("CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)");

$db->exec("CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    image_path TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
)");

$db->exec("CREATE TABLE IF NOT EXISTS connections (
    user_id INTEGER NOT NULL,
    friend_id INTEGER NOT NULL,
    PRIMARY KEY(user_id, friend_id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(friend_id) REFERENCES users(id)
)");

$db->exec("CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(sender_id) REFERENCES users(id),
    FOREIGN KEY(recipient_id) REFERENCES users(id)
)");

$db->exec("CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(post_id) REFERENCES posts(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
)");

$db->exec("CREATE TABLE IF NOT EXISTS likes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(post_id, user_id),
    FOREIGN KEY(post_id) REFERENCES posts(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
)");

// Helper function for escaping HTML
function escape($str) {
    return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}

// Ensure static directory exists
if (!file_exists('static')) {
    mkdir('static', 0777, true);
}

/**
 * LOGOUT (same file)
 */
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

/**
 * SIGNUP
 */
if (isset($_POST['action']) && $_POST['action'] === 'signup') {
    $username = $_POST['username'] ?? '';
    $password = password_hash($_POST['password'] ?? '', PASSWORD_DEFAULT);

    $stmt = $db->prepare('INSERT INTO users (username, password) VALUES (?, ?)');
    $stmt->bindValue(1, $username, SQLITE3_TEXT);
    $stmt->bindValue(2, $password, SQLITE3_TEXT);

    if ($stmt->execute()) {
        $_SESSION['user_id'] = $db->lastInsertRowID();
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
    $error = 'Signup failed. Username may already exist.';
}

/**
 * LOGIN
 */
if (isset($_POST['action']) && $_POST['action'] === 'login') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    $stmt = $db->prepare('SELECT id, password FROM users WHERE username = ?');
    $stmt->bindValue(1, $username, SQLITE3_TEXT);
    $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if ($result && password_verify($password, $result['password'])) {
        $_SESSION['user_id'] = $result['id'];
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
    $error = 'Login failed. Incorrect username or password.';
}

/**
 * CREATE A NEW POST
 */
if (isset($_POST['action']) && $_POST['action'] === 'post' && isset($_SESSION['user_id'])) {
    $content = $_POST['content'] ?? '';
    $image_path = null;

    // Handle file upload
    if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
        $file_tmp_path = $_FILES['image']['tmp_name'];
        $file_name = basename($_FILES['image']['name']);
        $file_ext = pathinfo($file_name, PATHINFO_EXTENSION);
        $allowed_exts = ['jpg', 'jpeg', 'png'];

        if (in_array(strtolower($file_ext), $allowed_exts)) {
            $new_file_name = time() . '-' . $_SESSION['user_id'] . '-' . $file_name;
            $destination = 'static/' . $new_file_name;
            if (move_uploaded_file($file_tmp_path, $destination)) {
                $image_path = $destination;
            }
        }
    }

    $stmt = $db->prepare('INSERT INTO posts (user_id, content, image_path) VALUES (?, ?, ?)');
    $stmt->bindValue(1, $_SESSION['user_id'], SQLITE3_INTEGER);
    $stmt->bindValue(2, $content, SQLITE3_TEXT);
    $stmt->bindValue(3, $image_path, SQLITE3_TEXT);
    $stmt->execute();
}

/**
 * ADD FRIEND (CONNECT)
 */
if (isset($_POST['action']) && $_POST['action'] === 'connect' && isset($_SESSION['user_id'])) {
    $friend_id = $_POST['friend_id'] ?? 0;
    $stmt = $db->prepare('INSERT OR IGNORE INTO connections (user_id, friend_id) VALUES (?, ?)');
    $stmt->bindValue(1, $_SESSION['user_id'], SQLITE3_INTEGER);
    $stmt->bindValue(2, $friend_id, SQLITE3_INTEGER);
    $stmt->execute();
}

/**
 * SEND A MESSAGE
 */
if (isset($_POST['action']) && $_POST['action'] === 'send_message' && isset($_SESSION['user_id'])) {
    $recipient_id = $_POST['recipient_id'] ?? 0;
    $content = $_POST['message_content'] ?? '';

    $stmt = $db->prepare('INSERT INTO messages (sender_id, recipient_id, content) VALUES (?, ?, ?)');
    $stmt->bindValue(1, $_SESSION['user_id'], SQLITE3_INTEGER);
    $stmt->bindValue(2, $recipient_id, SQLITE3_INTEGER);
    $stmt->bindValue(3, $content, SQLITE3_TEXT);
    $stmt->execute();
}

/**
 * ADD COMMENT
 */
if (isset($_POST['action']) && $_POST['action'] === 'comment' && isset($_SESSION['user_id'])) {
    $post_id = $_POST['post_id'] ?? 0;
    $comment_content = $_POST['comment_content'] ?? '';

    $stmt = $db->prepare('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)');
    $stmt->bindValue(1, $post_id, SQLITE3_INTEGER);
    $stmt->bindValue(2, $_SESSION['user_id'], SQLITE3_INTEGER);
    $stmt->bindValue(3, $comment_content, SQLITE3_TEXT);
    $stmt->execute();
}

/**
 * LIKE / UNLIKE
 */
if (isset($_POST['action']) && $_POST['action'] === 'like' && isset($_SESSION['user_id'])) {
    $post_id = $_POST['post_id'] ?? 0;

    // Check if this user already liked this post
    $check = $db->prepare('SELECT id FROM likes WHERE post_id = ? AND user_id = ?');
    $check->bindValue(1, $post_id, SQLITE3_INTEGER);
    $check->bindValue(2, $_SESSION['user_id'], SQLITE3_INTEGER);
    $existing_like = $check->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$existing_like) {
        // Insert new like
        $like_stmt = $db->prepare('INSERT INTO likes (post_id, user_id) VALUES (?, ?)');
        $like_stmt->bindValue(1, $post_id, SQLITE3_INTEGER);
        $like_stmt->bindValue(2, $_SESSION['user_id'], SQLITE3_INTEGER);
        $like_stmt->execute();
    } else {
        // If user already liked, remove it (toggle)
        $unlike_stmt = $db->prepare('DELETE FROM likes WHERE id = ?');
        $unlike_stmt->bindValue(1, $existing_like['id'], SQLITE3_INTEGER);
        $unlike_stmt->execute();
    }
}

/**
 * FETCH LOGGED-IN USER
 */
$user = null;
if (isset($_SESSION['user_id'])) {
    $stmt = $db->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->bindValue(1, $_SESSION['user_id'], SQLITE3_INTEGER);
    $user = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
}

/**
 * FETCH POSTS
 * If ?user_id=XX, show that user’s posts. Otherwise show feed (own + friends).
 */
$posts = [];
if ($user) {
    if (isset($_GET['user_id'])) {
        $chosen_user_id = (int) $_GET['user_id'];
        $stmt = $db->prepare('
            SELECT 
                posts.id AS post_id,
                posts.user_id AS post_user_id,
                posts.content,
                posts.image_path,
                posts.created_at,
                users.username,
                (SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id) AS like_count
            FROM posts
            JOIN users ON posts.user_id = users.id
            WHERE posts.user_id = ?
            ORDER BY posts.created_at DESC
        ');
        $stmt->bindValue(1, $chosen_user_id, SQLITE3_INTEGER);
    } else {
        $stmt = $db->prepare('
            SELECT 
                posts.id AS post_id,
                posts.user_id AS post_user_id,
                posts.content, 
                posts.image_path, 
                posts.created_at, 
                users.username,
                (SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id) AS like_count
            FROM posts
            JOIN users ON posts.user_id = users.id
            WHERE posts.user_id = ?
               OR posts.user_id IN (SELECT friend_id FROM connections WHERE user_id = ?)
            ORDER BY posts.created_at DESC
        ');
        $stmt->bindValue(1, $_SESSION['user_id'], SQLITE3_INTEGER);
        $stmt->bindValue(2, $_SESSION['user_id'], SQLITE3_INTEGER);
    }

    $result = $stmt->execute();
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        // Comments
        $post_id = $row['post_id'];
        $comments_stmt = $db->prepare('
            SELECT c.content, c.created_at, u.username
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.post_id = ?
            ORDER BY c.created_at ASC
        ');
        $comments_stmt->bindValue(1, $post_id, SQLITE3_INTEGER);
        $comments_result = $comments_stmt->execute();
        
        $comments = [];
        while ($crow = $comments_result->fetchArray(SQLITE3_ASSOC)) {
            $comments[] = $crow;
        }
        $row['comments'] = $comments;

        $posts[] = $row;
    }
}

/**
 * FETCH USERS TO CONNECT
 */
$others = [];
if ($user) {
    $stmt = $db->prepare('
        SELECT * 
        FROM users 
        WHERE id != ?
          AND id NOT IN (SELECT friend_id FROM connections WHERE user_id = ?)
    ');
    $stmt->bindValue(1, $_SESSION['user_id'], SQLITE3_INTEGER);
    $stmt->bindValue(2, $_SESSION['user_id'], SQLITE3_INTEGER);
    $result = $stmt->execute();
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $others[] = $row;
    }
}

/**
 * FETCH MESSAGES (inbox)
 */
$messages = [];
if ($user) {
    $stmt = $db->prepare('
        SELECT m.content, m.created_at, u.username AS sender
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.recipient_id = ?
        ORDER BY m.created_at DESC
    ');
    $stmt->bindValue(1, $_SESSION['user_id'], SQLITE3_INTEGER);
    $result = $stmt->execute();

    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $messages[] = $row;
    }
}

?>
<!DOCTYPE html>
<html>
<head>
    <title>jocarsa | salmon</title>
    <link rel="stylesheet" href="styles.css">
    <link rel="icon" type="image/svg+xml" href="https://jocarsa.com/static/logo/jocarsa | salmon.svg" />
</head>
<body>
<header>
    <h1>jocarsa | salmon</h1>

    <?php if ($user): ?>
        <!-- Search form (optional) -->
        <form method="get" style="display: inline;">
            <input type="text" name="search" placeholder="Search users...">
            <button type="submit">Search</button>
        </form>
        
        <span>¡Hola, <?= escape($user['username']) ?>!</span>
        <!-- Logout link calls this same file with ?action=logout -->
        <a href="<?= $_SERVER['PHP_SELF'] ?>?action=logout" style="margin-left: 15px;">Logout</a>
    <?php else: ?>
        <form method="post" style="display: inline;">
            <input type="hidden" name="action" value="login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Inicia sesión</button>
        </form>
        <form method="post" style="display: inline;">
            <input type="hidden" name="action" value="signup">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Crea una cuenta</button>
        </form>
    <?php endif; ?>
</header>

<?php if (!$user): ?>
    <?php if (!empty($error)): ?>
        <p style="color:red; text-align:center;"><?= escape($error) ?></p>
    <?php endif; ?>
<?php else: ?>
<main>
    <div class="left pane">
        <h3>Mis herramientas</h3>
        <ul>
            <li><a href="#">Mi perfil</a></li>
            <li><a href="#messages">Mensajes</a></li>
        </ul>

        <h3>Mis contactos</h3>
        <ul>
            <?php
            // fetch friends
            $stmt = $db->prepare('
                SELECT users.id, users.username
                FROM users
                JOIN connections ON users.id = connections.friend_id
                WHERE connections.user_id = ?
            ');
            $stmt->bindValue(1, $_SESSION['user_id'], SQLITE3_INTEGER);
            $result = $stmt->execute();
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                // Link to ?user_id=...
                echo '<li><a href="?user_id=' . $row['id'] . '">' . escape($row['username']) . '</a></li>';
            }
            ?>
        </ul>
    </div>

    <div class="center pane">
        <!-- If showing a single user's posts, let user go back -->
        <?php if (isset($_GET['user_id']) && $_GET['user_id'] != $_SESSION['user_id']): ?>
            <?php
            $chosen_user_id = (int) $_GET['user_id'];
            $u_stmt = $db->prepare('SELECT username FROM users WHERE id = ?');
            $u_stmt->bindValue(1, $chosen_user_id, SQLITE3_INTEGER);
            $u_row = $u_stmt->execute()->fetchArray(SQLITE3_ASSOC);
            ?>
            <h3>Publicaciones de <?= escape($u_row['username']) ?></h3>
            <p><a href="<?= $_SERVER['PHP_SELF'] ?>">← Volver al feed principal</a></p>
        <?php else: ?>
            <h3>Publicaciones</h3>
        <?php endif; ?>

        <!-- Create a new post -->
        <form method="post" enctype="multipart/form-data">
            <input type="hidden" name="action" value="post">
            <textarea name="content" placeholder="Escribe algo nuevo" required></textarea>
            <input type="file" name="image" accept=".jpg,.jpeg,.png">
            <button type="submit">Enviar</button>
        </form>

        <!-- Posts Loop -->
        <?php foreach ($posts as $post): ?>
            <div>
                <!-- Show user name as link to that user's posts -->
                <strong>
                    <a href="?user_id=<?= $post['post_user_id'] ?>">
                        <?= escape($post['username']) ?>
                    </a>:
                </strong>
                <p><?= escape($post['content']) ?></p>
                <?php if ($post['image_path']): ?>
                    <img src="<?= escape($post['image_path']) ?>" alt="Post Image">
                <?php endif; ?>
                <small><?= escape($post['created_at']) ?></small>
                
                <!-- Like button + like count -->
                <form method="post" style="display:inline;">
                    <input type="hidden" name="action" value="like">
                    <input type="hidden" name="post_id" value="<?= $post['post_id'] ?>">
                    <button type="submit">Me gusta (<?= $post['like_count'] ?>)</button>
                </form>
                
                <!-- Comments -->
                <div style="margin-top:10px;">
                    <strong>Comentarios:</strong>
                    <?php if (!empty($post['comments'])): ?>
                        <?php foreach ($post['comments'] as $comment): ?>
                            <div style="margin: 5px 0 0 15px;">
                                <strong><?= escape($comment['username']) ?>:</strong>
                                <p style="margin:0;"><?= escape($comment['content']) ?></p>
                                <small><?= escape($comment['created_at']) ?></small>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <p style="margin: 5px 0 0 15px; color:#999;">No hay comentarios.</p>
                    <?php endif; ?>

                    <!-- Form to add a comment -->
                    <form method="post" style="margin-top: 5px; margin-left:15px;">
                        <input type="hidden" name="action" value="comment">
                        <input type="hidden" name="post_id" value="<?= $post['post_id'] ?>">
                        <textarea name="comment_content" rows="2" placeholder="Escribe un comentario" required></textarea>
                        <button type="submit">Comentar</button>
                    </form>
                </div>
            </div>
        <?php endforeach; ?>
    </div>

    <div class="right pane">
        <h3>Conectar</h3>
        <ul>
            <?php foreach ($others as $other): ?>
                <li>
                    <?= escape($other['username']) ?>
                    <form method="post" style="display: inline;">
                        <input type="hidden" name="action" value="connect">
                        <input type="hidden" name="friend_id" value="<?= $other['id'] ?>">
                        <button type="submit">Connect</button>
                    </form>
                </li>
            <?php endforeach; ?>
        </ul>
    </div>

    <!-- Messages Pane (Inbox & Sending) -->
    <div class="right pane" id="messages">
        <h3>Mensajes</h3>
        <form method="post">
            <input type="hidden" name="action" value="send_message">
            <select name="recipient_id" required>
                <option value="" disabled selected>Selecciona un amigo</option>
                <?php
                // Re-use the friend list for messaging
                $stmt = $db->prepare('
                    SELECT users.id, users.username
                    FROM users
                    JOIN connections ON users.id = connections.friend_id
                    WHERE connections.user_id = ?
                ');
                $stmt->bindValue(1, $_SESSION['user_id'], SQLITE3_INTEGER);
                $result = $stmt->execute();
                while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                    echo '<option value="' . escape($row['id']) . '">' . escape($row['username']) . '</option>';
                }
                ?>
            </select>
            <textarea name="message_content" placeholder="Escribe tu mensaje" required></textarea>
            <button type="submit">Send</button>
        </form>

        <h4>Bandeja de entrada</h4>
        <?php foreach ($messages as $message): ?>
            <div>
                <strong>From <?= escape($message['sender']) ?>:</strong>
                <p><?= escape($message['content']) ?></p>
                <small><?= escape($message['created_at']) ?></small>
            </div>
        <?php endforeach; ?>
    </div>
</main>
<?php endif; ?>
</body>
</html>

