<?php
session_start();
include 'config.php';

// Security Check
if (!isset($_SESSION['username']) || !isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    header("Location: index.php");
    exit();
}

// --- HANDLE ACTIONS ---
$message = "";
$msg_type = ""; // 'success' or 'error'

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // 1. ADD NEW ARTIST / TEAM MEMBER
    if (isset($_POST['add_member'])) {
        $name = mysqli_real_escape_string($conn, $_POST['name']);
        $role = mysqli_real_escape_string($conn, $_POST['role']);
        $image_path = "";

        // Handle Image Upload
        if (isset($_FILES['profile_image']) && $_FILES['profile_image']['error'] === 0) {
            $allowed = ['jpg', 'jpeg', 'png', 'webp'];
            $filename = $_FILES['profile_image']['name'];
            $file_ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

            if (in_array($file_ext, $allowed)) {
                // Create unique filename
                $new_filename = uniqid('team_', true) . "." . $file_ext;
                // Target directory matching your about.php (uploads/team/)
                $upload_dir = 'uploads/team/';
                
                // Ensure upload directory exists
                if (!is_dir($upload_dir)) mkdir($upload_dir, 0777, true);

                if (move_uploaded_file($_FILES['profile_image']['tmp_name'], $upload_dir . $new_filename)) {
                    $image_path = $new_filename;
                } else {
                    $message = "Failed to upload image.";
                    $msg_type = "error";
                }
            } else {
                $message = "Invalid file type. Only JPG, PNG, and WEBP allowed.";
                $msg_type = "error";
            }
        } else {
            $message = "Please select an image.";
            $msg_type = "error";
        }

        if (empty($msg_type) && !empty($image_path)) { 
            $sql = "INSERT INTO about_artists (name, role, image_path) VALUES ('$name', '$role', '$image_path')";
            if (mysqli_query($conn, $sql)) {
                $message = "Artist added to About Page successfully!";
                $msg_type = "success";
            } else {
                $message = "Database error: " . mysqli_error($conn);
                $msg_type = "error";
            }
        }
    } 
    
    // 2. DELETE MEMBER
    elseif (isset($_POST['delete_id'])) {
        $id = (int)$_POST['delete_id'];
        
        // Get image path to delete file
        $query = mysqli_query($conn, "SELECT image_path FROM about_artists WHERE id = $id");
        $row = mysqli_fetch_assoc($query);
        if ($row && !empty($row['image_path'])) {
            $file = 'uploads/team/' . $row['image_path'];
            if (file_exists($file)) unlink($file);
        }

        mysqli_query($conn, "DELETE FROM about_artists WHERE id = $id");
        $message = "Member removed successfully.";
        $msg_type = "success";
    }
}

// Fetch All Members
$members = [];
$res = mysqli_query($conn, "SELECT * FROM about_artists ORDER BY id ASC");
while ($row = mysqli_fetch_assoc($res)) { $members[] = $row; }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage About Artists | ManCave Admin</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Nunito+Sans:wght@400;600;700;800&family=Playfair+Display:wght@600;700&family=Pacifico&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <style>
        /* =========================================
           INLINED ADMIN THEME (Consistent UI)
           ========================================= */
        :root {
            --bg-body: #f8f9fc;
            --text-main: #333333;
            --text-muted: #888888;
            --border-color: rgba(0,0,0,0.05);
            --card-bg: #ffffff;
            --shadow-color: rgba(0,0,0,0.05);
            --input-bg: #ffffff;
            --sidebar-bg: #ffffff; 
            --sidebar-text: #666666;
            --sidebar-active-bg: #cd853f;
            --sidebar-active-text: #ffffff;
            --sidebar-hover: #fff5eb;
            --logo-color: #333333;
            --accent: #cd853f;
            --accent-hover: #b07236;
            --sidebar-width: 280px;
            --radius-soft: 12px;
            --font-head: 'Playfair Display', serif;
            --font-main: 'Nunito Sans', sans-serif;
            --font-script: 'Pacifico', cursive;
        }

        [data-theme="dark"] {
            --bg-body: #121212;
            --text-main: #e0e0e0;
            --text-muted: #a0a0a0;
            --border-color: rgba(255,255,255,0.1);
            --card-bg: #1e1e1e;
            --shadow-color: rgba(0,0,0,0.3);
            --input-bg: #2a2a2a;
            --sidebar-bg: #1a1a1a; 
            --sidebar-text: #b0b0b0;
            --sidebar-active-bg: #cd853f;
            --sidebar-active-text: #ffffff;
            --sidebar-hover: #2c2c2c;
            --logo-color: #ffffff;
        }

        body {
            background-color: var(--bg-body);
            color: var(--text-main);
            font-family: var(--font-main);
            transition: background-color 0.3s ease, color 0.3s ease;
            margin: 0; padding: 0;
        }

        a { text-decoration: none; color: inherit; transition: 0.3s; }
        ul { list-style: none; padding: 0; margin: 0; }
        * { box-sizing: border-box; }

        /* === SIDEBAR === */
        .sidebar {
            position: fixed; top: 0; left: 0; bottom: 0;
            width: var(--sidebar-width);
            background: var(--sidebar-bg);
            padding: 30px 20px;
            display: flex; flex-direction: column;
            border-right: 1px solid var(--border-color);
            box-shadow: 5px 0 25px var(--shadow-color);
            z-index: 1000;
            transition: all 0.3s ease;
        }

        .sidebar-header {
            text-align: center; margin-bottom: 40px; padding-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .sidebar-logo {
            text-decoration: none; display: flex; flex-direction: column; align-items: center; line-height: 1;
        }
        .logo-top { font-family: var(--font-head); font-size: 0.85rem; font-weight: 700; color: var(--text-muted); letter-spacing: 2px; margin-bottom: -5px; }
        .logo-main { font-family: var(--font-script); font-size: 3rem; font-weight: 400; color: var(--logo-color); transform: rotate(-4deg); text-shadow: 0 3px 6px rgba(0,0,0,0.15); margin: 0; padding: 5px 0; }
        .logo-red { color: #ff4d4d; }
        .logo-bottom { font-family: var(--font-main); font-size: 0.75rem; font-weight: 800; color: var(--text-muted); letter-spacing: 8px; text-transform: uppercase; margin-top: -2px; margin-right: -8px; }

        .sidebar-nav { flex: 1; overflow-y: auto; }
        .sidebar-nav li { margin-bottom: 8px; }
        .sidebar-nav a {
            display: flex; align-items: center; gap: 15px; padding: 14px 20px;
            color: var(--sidebar-text); font-weight: 700; font-size: 0.95rem;
            border-radius: var(--radius-soft); transition: all 0.3s ease;
        }
        .sidebar-nav a i { width: 20px; text-align: center; font-size: 1.1rem; opacity: 0.7; }
        .sidebar-nav a:hover { background: var(--sidebar-hover); color: var(--accent); transform: translateX(3px); }
        .sidebar-nav a:hover i { color: var(--accent); opacity: 1; }
        .sidebar-nav li.active a { background: var(--sidebar-active-bg); color: var(--sidebar-active-text); box-shadow: 0 4px 12px rgba(205, 133, 63, 0.3); }
        .sidebar-nav li.active a i { color: var(--sidebar-active-text); opacity: 1; }

        .sidebar-footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border-color); }
        .btn-logout {
            display: flex; align-items: center; justify-content: center; gap: 10px; width: 100%;
            padding: 12px; background: rgba(255, 77, 77, 0.1); color: #ff4d4d;
            border-radius: var(--radius-soft); font-weight: 700; transition: 0.3s;
        }
        .btn-logout:hover { background: #ff4d4d; color: white; transform: translateY(-2px); box-shadow: 0 4px 10px rgba(255, 77, 77, 0.2); }

        /* === MAIN CONTENT === */
        .main-content {
            margin-left: var(--sidebar-width);
            padding: 30px 40px;
            width: calc(100% - var(--sidebar-width));
        }

        .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; }
        .page-header h1 { font-family: var(--font-head); font-size: 2.2rem; color: var(--text-main); margin: 0 0 5px 0; }
        .page-header p { color: var(--text-muted); font-size: 1rem; margin: 0; }

        .header-actions { display: flex; align-items: center; gap: 20px; }
        .icon-btn {
            background: var(--card-bg); width: 45px; height: 45px; border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.2rem; color: var(--text-muted); cursor: pointer; border: 1px solid var(--border-color);
            transition: 0.3s; box-shadow: 0 2px 5px var(--shadow-color);
        }
        .icon-btn:hover { color: var(--accent); transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.1); }

        .user-profile {
            display: flex; align-items: center; gap: 15px; background: var(--card-bg);
            padding: 6px 6px 6px 20px; border-radius: 50px; border: 1px solid var(--border-color);
            box-shadow: 0 2px 5px var(--shadow-color);
        }
        .profile-info { text-align: right; line-height: 1.2; }
        .profile-info .name { display: block; font-weight: 800; font-size: 0.9rem; color: var(--text-main); }
        .profile-info .role { font-size: 0.75rem; color: var(--accent); font-weight: 700; text-transform: uppercase; }
        .avatar img { width: 40px; height: 40px; border-radius: 50%; border: 2px solid var(--bg-body); }

        /* === LAYOUT & CARDS === */
        .dashboard-layout { display: grid; grid-template-columns: 2fr 1fr; gap: 30px; }
        .card {
            background: var(--card-bg); border-radius: var(--radius-soft);
            box-shadow: 0 5px 15px var(--shadow-color); padding: 30px;
            border: 1px solid var(--border-color); h-100;
        }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; padding-bottom: 15px; border-bottom: 1px solid var(--border-color); }
        .card-header h3 { font-size: 1.2rem; font-weight: 800; color: var(--text-main); margin: 0; }

        /* Forms */
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; font-weight: 700; font-size: 0.9rem; color: var(--text-main); }
        .form-group input, .form-group textarea {
            width: 100%; padding: 12px 15px; background: var(--input-bg);
            border: 1px solid var(--border-color); border-radius: 8px;
            color: var(--text-main); font-family: var(--font-main); font-size: 0.95rem;
            transition: 0.3s;
        }
        .form-group input:focus, .form-group textarea:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(205, 133, 63, 0.1); }
        
        .btn-primary {
            background: var(--accent); color: white; padding: 12px 25px;
            border: none; border-radius: 8px; cursor: pointer; width: 100%;
            font-weight: 700; font-size: 1rem; transition: 0.3s; display: flex; align-items: center; justify-content: center; gap: 10px;
        }
        .btn-primary:hover { background: var(--accent-hover); transform: translateY(-2px); box-shadow: 0 5px 15px rgba(205, 133, 63, 0.3); }

        /* Tables */
        .table-card { padding: 0; overflow: hidden; }
        .table-card .card-header { padding: 25px; margin: 0; }
        .table-responsive { overflow-x: auto; }
        .styled-table { width: 100%; border-collapse: collapse; }
        .styled-table th {
            text-align: left; padding: 18px 25px; background: var(--bg-body);
            color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px;
            border-bottom: 1px solid var(--border-color); font-weight: 700;
        }
        .styled-table td { padding: 18px 25px; border-bottom: 1px solid var(--border-color); color: var(--text-main); vertical-align: middle; }
        .styled-table tr:hover { background: rgba(0,0,0,0.02); }
        
        .btn-icon { width: 32px; height: 32px; border-radius: 6px; border: none; display: flex; align-items: center; justify-content: center; cursor: pointer; transition: 0.2s; }
        .btn-icon.delete { background: rgba(239, 68, 68, 0.1); color: #ef4444; }
        .btn-icon.delete:hover { background: #ef4444; color: white; }

        /* Notifications */
        .notif-wrapper { position: relative; }
        .notif-bell .dot { position: absolute; top: 0; right: 0; background: #ff4d4d; color: white; font-size: 0.6rem; font-weight: 700; border-radius: 50%; min-width: 16px; height: 16px; display: flex; align-items: center; justify-content: center; border: 2px solid var(--card-bg); }
        .notif-dropdown { display: none; position: absolute; right: -10px; top: 60px; width: 320px; background: var(--card-bg); border-radius: 12px; box-shadow: 0 15px 40px rgba(0,0,0,0.15); border: 1px solid var(--border-color); z-index: 1100; overflow: hidden; }
        .notif-dropdown.active { display: block; }
        .notif-header { padding: 15px; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; font-weight: 700; color: var(--text-main); background: var(--bg-body); }
        .notif-list { max-height: 300px; overflow-y: auto; }
        .notif-item { padding: 15px; border-bottom: 1px solid var(--border-color); cursor: pointer; transition: 0.2s; color: var(--text-main); }
        .notif-item:hover { background: var(--bg-body); }
        .notif-item.unread { border-left: 3px solid var(--accent); background: rgba(205, 133, 63, 0.05); }
        .no-notif { padding: 20px; text-align: center; color: var(--text-muted); font-style: italic; }
        .small-btn { background: none; border: none; color: var(--accent); font-weight: 700; font-size: 0.75rem; cursor: pointer; text-transform: uppercase; }

        /* Alert */
        .alert-box { padding: 15px 20px; border-radius: var(--radius-soft); margin-bottom: 25px; color: #fff; display: flex; align-items: center; gap: 10px; font-weight: 600; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }
        .alert-success { background: #10b981; }
        .alert-error { background: #ef4444; }

        /* === SPECIFIC TO THIS PAGE === */
        .preview-img { width: 60px; height: 60px; border-radius: 50%; object-fit: cover; border: 2px solid var(--accent); }
        
        .file-upload-wrapper {
            position: relative; width: 100%; height: 150px;
            border: 2px dashed var(--border-color); border-radius: var(--radius-soft);
            display: flex; align-items: center; justify-content: center; flex-direction: column;
            background: var(--bg-body); transition: 0.3s; cursor: pointer;
        }
        .file-upload-wrapper:hover { border-color: var(--accent); background: rgba(205, 133, 63, 0.05); }
        .file-upload-wrapper input[type="file"] { position: absolute; width: 100%; height: 100%; opacity: 0; cursor: pointer; }
        .file-upload-text { color: var(--text-muted); font-weight: 700; margin-top: 10px; font-size: 0.9rem; }
        .file-upload-icon { font-size: 2rem; color: var(--accent); }

        @media (max-width: 1024px) {
            .dashboard-layout { grid-template-columns: 1fr; }
            .sidebar { width: 80px; padding: 20px 10px; }
            .sidebar-logo span:not(.logo-main), .logo-bottom, .sidebar-nav span, .sidebar-footer span { display: none; }
            .logo-main { font-size: 1.5rem; transform: rotate(0); }
            .sidebar-nav a { justify-content: center; padding: 15px; }
            .sidebar-nav a:hover { transform: none; }
            .main-content { margin-left: 80px; width: calc(100% - 80px); }
        }
    </style>
</head>
<body>
    <script>
        // Init Theme
        (function() {
            const savedTheme = localStorage.getItem('adminTheme');
            if (savedTheme === 'dark') {
                document.documentElement.setAttribute('data-theme', 'dark');
            }
        })();
    </script>

    <aside class="sidebar">
        <div class="sidebar-header">
            <a href="index.php" class="sidebar-logo">
                <span class="logo-top">THE</span>
                <span class="logo-main"><span class="logo-red">M</span>an<span class="logo-red">C</span>ave</span>
                <span class="logo-bottom">GALLERY</span>
            </a>
        </div>
        <nav class="sidebar-nav">
            <ul>
                <li><a href="admin.php"><i class="fas fa-home"></i> <span>Dashboard</span></a></li>
                <li><a href="reservations.php"><i class="fas fa-calendar-check"></i> <span>Appointments</span></a></li>
                <li><a href="content.php"><i class="fas fa-layer-group"></i> <span>Website Content</span></a></li>
                <li><a href="manage_hero.php"><i class="fas fa-images"></i> <span>Manage Slider</span></a></li>
                <li><a href="manage_news.php"><i class="fas fa-newspaper"></i> <span>Gallery Updates</span></a></li>
                <li><a href="manage_team.php"><i class="fas fa-user-tie"></i> <span>Manage Artists</span></a></li>
                <li class="active"><a href="manage_about_artists.php"><i class="fas fa-users-cog"></i> <span>About: Meet Artists</span></a></li>
                
                <li><a href="users.php"><i class="fas fa-users"></i> <span>Customers & Staff</span></a></li>
                <li><a href="feedback.php"><i class="fas fa-comments"></i> <span>Message & Feedback</span></a></li>
                <li><a href="trash.php"><i class="fas fa-trash-alt"></i> <span>Recycle Bin</span></a></li>
            </ul>
        </nav>
        <div class="sidebar-footer">
            <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span>Logout</span></a>
        </div>
    </aside>

    <main class="main-content">
        
        <header class="top-bar">
            <div class="page-header">
                <h1>Meet The Artists</h1>
                <p>Manage the team displayed on the "About Us" page.</p>
            </div>
            
            <div class="header-actions">
                <button class="icon-btn" id="themeToggle" title="Toggle Dark Mode">
                    <i class="fas fa-moon"></i>
                </button>

                <div class="notif-wrapper">
                    <div class="icon-btn notif-bell" id="adminNotifBtn">
                        <i class="far fa-bell"></i>
                        <span class="dot" id="adminNotifBadge" style="display:none;">0</span>
                    </div>
                    
                    <div class="notif-dropdown" id="adminNotifDropdown">
                        <div class="notif-header">
                            <span>Notifications</span>
                            <button id="adminMarkAllRead" class="small-btn">Mark all read</button>
                        </div>
                        <ul class="notif-list" id="adminNotifList">
                            <li class="no-notif">Loading...</li>
                        </ul>
                    </div>
                </div>

                <div class="user-profile">
                    <div class="profile-info">
                        <span class="name"><?php echo htmlspecialchars($_SESSION['username']); ?></span>
                        <span class="role">Admin</span>
                    </div>
                    <div class="avatar">
                        <img src="https://ui-avatars.com/api/?name=<?php echo urlencode($_SESSION['username']); ?>&background=cd853f&color=fff" alt="Admin">
                    </div>
                </div>
            </div>
        </header>

        <?php if($message): ?>
            <div class="alert-box <?php echo $msg_type == 'success' ? 'alert-success' : 'alert-error'; ?>">
                <i class="fas <?php echo $msg_type == 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'; ?>"></i>
                <?php echo $message; ?>
            </div>
        <?php endif; ?>

        <div class="dashboard-layout">
            <div class="col-chart" style="grid-column: span 1;">
                <div class="card table-card">
                    <div class="card-header">
                        <h3>Current Team Members</h3>
                    </div>
                    <div class="table-responsive">
                        <table class="styled-table">
                            <thead>
                                <tr>
                                    <th width="80">Image</th>
                                    <th>Name</th>
                                    <th>Role / Title</th>
                                    <th width="80">Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if(empty($members)): ?>
                                    <tr><td colspan="4" class="text-center" style="padding: 30px; color: var(--text-muted);">No members found. Add one!</td></tr>
                                <?php else: foreach($members as $row): ?>
                                <tr>
                                    <td>
                                        <img src="uploads/team/<?php echo htmlspecialchars($row['image_path']); ?>" class="preview-img" alt="Artist">
                                    </td>
                                    <td>
                                        <strong style="font-size:1rem; color:var(--text-main);"><?php echo htmlspecialchars($row['name']); ?></strong>
                                    </td>
                                    <td>
                                        <span style="color:var(--text-muted); font-weight:600; text-transform:uppercase; font-size:0.8rem; letter-spacing:1px;"><?php echo htmlspecialchars($row['role']); ?></span>
                                    </td>
                                    <td>
                                        <form method="POST" onsubmit="return confirm('Remove this artist from the About page?');">
                                            <input type="hidden" name="delete_id" value="<?php echo $row['id']; ?>">
                                            <button type="submit" class="btn-icon delete" title="Delete"><i class="fas fa-trash"></i></button>
                                        </form>
                                    </td>
                                </tr>
                                <?php endforeach; endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div class="col-side" style="grid-column: span 1;">
                <div class="card">
                    <div class="card-header">
                        <h3>Add New Artist</h3>
                    </div>
                    <form method="POST" enctype="multipart/form-data">
                        <div class="form-group">
                            <label>Profile Photo</label>
                            <div class="file-upload-wrapper">
                                <input type="file" name="profile_image" accept="image/*" onchange="previewFile(this)" required>
                                <i class="fas fa-cloud-upload-alt file-upload-icon"></i>
                                <span class="file-upload-text" id="fileLabel">Upload Photo</span>
                            </div>
                        </div>

                        <div class="form-group">
                            <label>Full Name</label>
                            <input type="text" name="name" required placeholder="e.g. Alexander Ford">
                        </div>

                        <div class="form-group">
                            <label>Role / Title</label>
                            <input type="text" name="role" required placeholder="e.g. Lead Sculptor">
                        </div>

                        <button type="submit" name="add_member" class="btn-primary">
                            <i class="fas fa-plus-circle"></i> Add to Team
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </main>

    <script>
        // File Upload Preview
        function previewFile(input) {
            const label = document.getElementById('fileLabel');
            if (input.files && input.files[0]) {
                label.innerText = "Selected: " + input.files[0].name;
                label.style.color = "var(--accent)";
                const icon = input.parentElement.querySelector('.file-upload-icon');
                icon.className = "fas fa-check-circle file-upload-icon";
                icon.style.color = "#10b981";
            }
        }

        // --- GLOBAL ADMIN SCRIPTS ---
        document.addEventListener('DOMContentLoaded', () => {
            
            // 1. Dark Mode Logic
            const themeToggleBtn = document.getElementById('themeToggle');
            const themeIcon = themeToggleBtn.querySelector('i');
            
            if(document.documentElement.getAttribute('data-theme') === 'dark') {
                themeIcon.classList.replace('fa-moon', 'fa-sun');
            }

            themeToggleBtn.addEventListener('click', () => {
                const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
                if (isDark) {
                    document.documentElement.removeAttribute('data-theme');
                    localStorage.setItem('adminTheme', 'light');
                    themeIcon.classList.replace('fa-sun', 'fa-moon');
                } else {
                    document.documentElement.setAttribute('data-theme', 'dark');
                    localStorage.setItem('adminTheme', 'dark');
                    themeIcon.classList.replace('fa-moon', 'fa-sun');
                }
            });

            // 2. Notification Logic
            const notifBtn = document.getElementById('adminNotifBtn');
            const notifDropdown = document.getElementById('adminNotifDropdown');
            const notifBadge = document.getElementById('adminNotifBadge');
            const notifList = document.getElementById('adminNotifList');
            const markAllBtn = document.getElementById('adminMarkAllRead');

            if(notifBtn) {
                notifBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    notifDropdown.classList.toggle('active');
                });

                function fetchNotifications() {
                    fetch('fetch_notifications.php')
                        .then(res => res.json())
                        .then(data => {
                            if (data.status === 'success') {
                                if (data.unread_count > 0) {
                                    notifBadge.innerText = data.unread_count;
                                    notifBadge.style.display = 'flex';
                                } else {
                                    notifBadge.style.display = 'none';
                                }
                                notifList.innerHTML = '';
                                if (data.notifications.length === 0) {
                                    notifList.innerHTML = '<li class="no-notif">No new notifications</li>';
                                } else {
                                    data.notifications.forEach(notif => {
                                        const li = document.createElement('li');
                                        li.className = `notif-item ${notif.is_read == 0 ? 'unread' : ''}`;
                                        li.innerHTML = `
                                            <div class="notif-msg">${notif.message}</div>
                                            <div class="notif-time">${notif.created_at}</div>
                                            <button class="btn-notif-close" title="Delete">&times;</button>
                                        `;
                                        li.addEventListener('click', (e) => {
                                            if (e.target.classList.contains('btn-notif-close')) return;
                                            const formData = new FormData();
                                            formData.append('id', notif.id);
                                            fetch('mark_as_read.php', { method: 'POST', body: formData }).then(() => fetchNotifications());
                                        });
                                        li.querySelector('.btn-notif-close').addEventListener('click', (e) => {
                                            e.stopPropagation();
                                            if(!confirm('Delete this notification?')) return;
                                            const formData = new FormData();
                                            formData.append('id', notif.id);
                                            fetch('delete_notifications.php', { method: 'POST', body: formData }).then(res => res.json()).then(d => { if(d.status === 'success') fetchNotifications(); });
                                        });
                                        notifList.appendChild(li);
                                    });
                                }
                            }
                        });
                }

                if (markAllBtn) {
                    markAllBtn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        fetch('mark_all_as_read.php', { method: 'POST' }).then(() => fetchNotifications());
                    });
                }

                window.addEventListener('click', () => {
                    if (notifDropdown.classList.contains('active')) notifDropdown.classList.remove('active');
                });
                notifDropdown.addEventListener('click', (e) => e.stopPropagation());

                fetchNotifications();
                setInterval(fetchNotifications, 30000);
            }
        });
    </script>
</body>
</html>