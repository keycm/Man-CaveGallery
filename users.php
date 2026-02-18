<?php
session_start();
include 'config.php';

// Security Check - Only Admins can access this page
if (!isset($_SESSION['username']) || !isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    header("Location: index.php");
    exit();
}

// --- SORTING LOGIC ---
$sortOption = $_GET['sort'] ?? 'id_asc';
$orderBy = "id ASC"; // Default

switch ($sortOption) {
    case 'id_desc': $orderBy = "id DESC"; break;
    case 'name_asc': $orderBy = "username ASC"; break;
    case 'name_desc': $orderBy = "username DESC"; break;
    case 'role_asc': $orderBy = "role ASC"; break;
    case 'role_desc': $orderBy = "role DESC"; break;
    case 'id_asc': default: $orderBy = "id ASC"; break;
}

// Fetch Users with Sorting
$users = [];
$sql = "SELECT id, username, email, role FROM users ORDER BY $orderBy";
$result = mysqli_query($conn, $sql);
if ($result) {
    while ($row = mysqli_fetch_assoc($result)) {
        $users[] = $row;
    }
}

// Time-based greeting
$hour = date('H');
if ($hour < 12) $greeting = "Good Morning";
elseif ($hour < 18) $greeting = "Good Afternoon";
else $greeting = "Good Evening";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Customers & Staff | ManCave Admin</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Nunito+Sans:wght@400;600;700;800&family=Playfair+Display:wght@600;700&family=Pacifico&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="admin_new_style.css">
    
    <style>
        /* =========================================
           INLINED ADMIN THEME (Matches manage_news.php)
           ========================================= */
        :root {
            /* Base Colors */
            --bg-body: #f8f9fc;
            --text-main: #333333;
            --text-muted: #888888;
            --border-color: rgba(0,0,0,0.05);
            --card-bg: #ffffff;
            --shadow-color: rgba(0,0,0,0.05);
            --input-bg: #ffffff;

            /* Sidebar Colors */
            --sidebar-bg: #ffffff; 
            --sidebar-text: #666666;
            --sidebar-active-bg: #cd853f;
            --sidebar-active-text: #ffffff;
            --sidebar-hover: #fff5eb;
            --logo-color: #333333;
            
            /* Accents */
            --accent: #cd853f;
            --accent-hover: #b07236;
            
            /* Status Colors */
            --green: #10b981;
            --red: #ef4444;
            --blue: #3b82f6;
            --orange: #f59e0b;
            
            /* Dimensions */
            --sidebar-width: 280px;
            --radius-soft: 12px;
            
            /* Fonts */
            --font-head: 'Playfair Display', serif;
            --font-main: 'Nunito Sans', sans-serif;
            --font-script: 'Pacifico', cursive;
        }

        /* Dark Mode Overrides */
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

        /* === SPECIFIC TO USER MANAGER === */
        
        /* Controls Bar */
        .controls-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; flex-wrap: wrap; gap: 15px; }
        .search-group { display: flex; gap: 10px; flex: 1; max-width: 600px; }
        .search-wrapper { position: relative; flex: 1; }
        .search-wrapper input { 
            width: 100%; padding: 12px 15px 12px 45px; border-radius: 50px; 
            border: 1px solid var(--border-color); outline: none; 
            background: var(--input-bg); color: var(--text-main); font-family: var(--font-main);
        }
        .search-wrapper i { position: absolute; left: 18px; top: 50%; transform: translateY(-50%); color: var(--text-muted); }
        
        .sort-select { 
            padding: 0 20px; border-radius: 50px; border: 1px solid var(--border-color); 
            background: var(--input-bg); color: var(--text-main); font-weight: 700; 
            cursor: pointer; outline: none; height: 45px; font-family: var(--font-main);
        }

        .btn-add { 
            background: var(--accent); color: white; padding: 12px 25px; border-radius: 50px; 
            font-weight: 700; border: none; cursor: pointer; display: flex; align-items: center; 
            gap: 10px; transition: 0.3s; box-shadow: 0 4px 15px rgba(205, 133, 63, 0.3); font-family: var(--font-main);
        }
        .btn-add:hover { background: var(--accent-hover); transform: translateY(-2px); }

        /* Tables */
        .card { background: var(--card-bg); border-radius: var(--radius-soft); box-shadow: 0 5px 15px var(--shadow-color); padding: 30px; border: 1px solid var(--border-color); }
        .table-responsive { overflow-x: auto; }
        .styled-table { width: 100%; border-collapse: collapse; }
        .styled-table th {
            text-align: left; padding: 18px 25px; background: var(--bg-body);
            color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px;
            border-bottom: 1px solid var(--border-color); font-weight: 700;
        }
        .styled-table td { padding: 18px 25px; border-bottom: 1px solid var(--border-color); color: var(--text-main); vertical-align: middle; }
        .styled-table tr:hover { background: rgba(0,0,0,0.02); }

        .user-cell { display: flex; align-items: center; gap: 12px; }
        .user-avatar-sm { width: 35px; height: 35px; background: var(--accent); color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 0.9rem; }
        .id-badge { background: var(--bg-body); padding: 4px 8px; border-radius: 4px; font-weight: 700; font-size: 0.8rem; color: var(--text-muted); border: 1px solid var(--border-color); }

        /* Status Badges */
        .status-badge { padding: 5px 12px; border-radius: 50px; font-size: 0.75rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; display: inline-block; }
        .role-admin { background: rgba(239, 68, 68, 0.1); color: var(--red); }
        .role-manager { background: rgba(59, 130, 246, 0.1); color: var(--blue); }
        .role-user { background: rgba(16, 185, 129, 0.1); color: var(--green); }

        /* Actions */
        .actions { display: flex; gap: 8px; justify-content: flex-end; }
        .btn-icon { width: 32px; height: 32px; border-radius: 6px; border: none; display: flex; align-items: center; justify-content: center; cursor: pointer; transition: 0.2s; }
        .btn-icon.edit { background: rgba(59, 130, 246, 0.1); color: var(--blue); }
        .btn-icon.delete { background: rgba(239, 68, 68, 0.1); color: var(--red); }
        .btn-icon:hover { transform: translateY(-2px); opacity: 0.8; }

        /* Notifications & Modals */
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
        .btn-notif-close { background: none; border: none; color: var(--text-muted); font-size: 1.2rem; cursor: pointer; position: absolute; top:12px; right:12px; }
        .btn-notif-close:hover { color: #ff4d4d; }

        /* Modals */
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; opacity: 0; visibility: hidden; transition: 0.3s; z-index: 2000; }
        .modal-overlay.active { opacity: 1; visibility: visible; }
        .modal-card { background: var(--card-bg); border: 1px solid var(--border-color); color: var(--text-main); }
        
        .modal-card.form-modal { width: 450px; max-width: 95%; padding: 30px; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.2); transform: translateY(20px); transition: 0.3s; }
        .modal-overlay.active .modal-card.form-modal { transform: translateY(0); }
        
        .modal-card.small { width: 400px; max-width: 90%; border-radius: 16px; padding: 35px; text-align: center; box-shadow: 0 20px 60px rgba(0,0,0,0.2); transform: translateY(20px); transition: 0.3s; }
        .modal-overlay.active .modal-card.small { transform: translateY(0); }
        
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; border-bottom: 1px solid var(--border-color); padding-bottom: 15px; }
        .modal-header h3 { font-family: var(--font-head); font-size: 1.5rem; color: var(--text-main); margin: 0; }
        .btn-close-modal { background: none; border: none; font-size: 1.8rem; cursor: pointer; color: var(--text-muted); line-height: 1; }
        
        .modal-header-icon { width: 70px; height: 70px; border-radius: 50%; margin: 0 auto 20px; display: flex; align-items: center; justify-content: center; font-size: 2rem; }
        .delete-icon { background: rgba(239, 68, 68, 0.1); color: var(--red); }
        .success-icon { background: rgba(16, 185, 129, 0.1); color: var(--green); }
        
        .modal-card.small h3 { font-family: var(--font-head); font-size: 1.5rem; margin-bottom: 10px; color: var(--text-main); }
        .modal-card.small p { color: var(--text-muted); }
        
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; font-weight: 700; font-size: 0.9rem; color: var(--text-muted); }
        .form-group input, .form-group select { 
            width: 100%; padding: 12px 15px; border: 1px solid var(--border-color); 
            border-radius: 8px; font-size: 0.95rem; transition: 0.3s; 
            background: var(--input-bg); color: var(--text-main); font-family: var(--font-main);
        }
        .form-group input:focus, .form-group select:focus { border-color: var(--accent); outline: none; }

        .btn-group { display: flex; gap: 10px; justify-content: center; margin-top: 20px; }
        .btn-friendly { padding: 12px 25px; border-radius: 8px; font-weight: 700; border: none; cursor: pointer; transition: 0.2s; font-size: 0.95rem; font-family: var(--font-main); }
        .btn-friendly:hover { transform: translateY(-2px); opacity: 0.9; }

        @media (max-width: 1024px) {
            .sidebar { width: 80px; padding: 20px 10px; }
            .sidebar-logo span:not(.logo-main), .logo-bottom, .sidebar-nav span, .sidebar-footer span { display: none; }
            .logo-main { font-size: 1.5rem; transform: rotate(0); }
            .sidebar-nav a { justify-content: center; padding: 15px; }
            .main-content { margin-left: 80px; width: calc(100% - 80px); }
        }
    </style>
</head>
<body>
    <script>
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
                <li><a href="manage_about_artists.php"><i class="fas fa-users-cog"></i> <span>About: Meet Artists</span></a></li>
                <li class="active"><a href="users.php"><i class="fas fa-users"></i> <span>Customers & Staff</span></a></li>
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
                <h1>User Management</h1>
                <p>Manage customers, managers, and administrators.</p>
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
                        <span class="name">Administrator</span>
                        <span class="role">Super Admin</span>
                    </div>
                    <div class="avatar"><img src="https://ui-avatars.com/api/?name=Admin&background=cd853f&color=fff" alt="Admin"></div>
                </div>
            </div>
        </header>

        <div class="controls-bar">
            <form method="GET" class="search-group">
                <div class="search-wrapper">
                    <i class="fas fa-search"></i>
                    <input type="text" id="userSearch" placeholder="Search by name or email...">
                </div>
                
                <select name="sort" class="sort-select" onchange="this.form.submit()">
                    <option value="id_asc" <?= $sortOption == 'id_asc' ? 'selected' : '' ?>>ID (Oldest)</option>
                    <option value="id_desc" <?= $sortOption == 'id_desc' ? 'selected' : '' ?>>ID (Newest)</option>
                    <option value="name_asc" <?= $sortOption == 'name_asc' ? 'selected' : '' ?>>Name (A-Z)</option>
                    <option value="name_desc" <?= $sortOption == 'name_desc' ? 'selected' : '' ?>>Name (Z-A)</option>
                    <option value="role_asc" <?= $sortOption == 'role_asc' ? 'selected' : '' ?>>Role (A-Z)</option>
                    <option value="role_desc" <?= $sortOption == 'role_desc' ? 'selected' : '' ?>>Role (Z-A)</option>
                </select>
            </form>

            <button class="btn-add" onclick="openAddModal()">
                <i class="fas fa-user-plus"></i> Add New User
            </button>
        </div>

        <div class="card table-card">
            <div class="table-responsive">
                <table class="styled-table" id="usersTable">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>User Profile</th>
                            <th>Email Address</th>
                            <th>Role</th>
                            <th style="text-align: right;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($users)): ?>
                            <tr><td colspan="5" class="text-center" style="padding:40px; color:var(--text-muted);">No users found.</td></tr>
                        <?php else: ?>
                            <?php foreach ($users as $user): 
                                $role = strtolower($user['role']);
                                $roleClass = 'role-user'; 
                                $roleLabel = 'Collector';

                                if ($role === 'admin') {
                                    $roleClass = 'role-admin'; 
                                    $roleLabel = 'Admin';
                                } elseif ($role === 'manager') {
                                    $roleClass = 'role-manager';
                                    $roleLabel = 'Manager';
                                }

                                $initial = strtoupper(substr($user['username'], 0, 1));
                            ?>
                            <tr data-id="<?= $user['id'] ?>" 
                                data-username="<?= htmlspecialchars($user['username']) ?>"
                                data-email="<?= htmlspecialchars($user['email']) ?>"
                                data-role="<?= htmlspecialchars($role) ?>">
                                
                                <td><span class="id-badge">#<?= $user['id'] ?></span></td>
                                
                                <td>
                                    <div class="user-cell">
                                        <div class="user-avatar-sm"><?= $initial ?></div>
                                        <strong><?= htmlspecialchars($user['username']) ?></strong>
                                    </div>
                                </td>
                                
                                <td><?= htmlspecialchars($user['email']) ?></td>
                                
                                <td>
                                    <span class="status-badge <?= $roleClass ?>"><?= $roleLabel ?></span>
                                </td>
                                
                                <td style="text-align: right;">
                                    <div class="actions">
                                        <button class="btn-icon edit" onclick="editUser(this)" title="Edit User">
                                            <i class="fas fa-pen"></i>
                                        </button>
                                        
                                        <?php if ($user['id'] != $_SESSION['user_id']): ?>
                                            <button class="btn-icon delete" onclick="confirmDelete(<?= $user['id'] ?>)" title="Move to Trash">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        <?php endif; ?>
                                    </div>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

    </main>

    <div class="modal-overlay" id="userModal">
        <div class="modal-card form-modal">
            <div class="modal-header">
                <h3 id="modalTitle">Add New User</h3>
                <button class="btn-close-modal" onclick="closeModal('userModal')">&times;</button>
            </div>
            <form id="userForm">
                <input type="hidden" id="userId" name="id">
                <input type="hidden" id="actionType" name="action" value="add">
                
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" id="username" name="username" required placeholder="Enter full name">
                </div>
                
                <div class="form-group">
                    <label>Email Address</label>
                    <input type="email" id="email" name="email" required placeholder="name@example.com">
                </div>
                
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="password" name="password" placeholder="Leave blank to keep current">
                    <small style="color:var(--text-muted); font-size:0.8rem; margin-top:5px; display:block;">
                        Minimum 8 characters. Required for new users.
                    </small>
                </div>
                
                <div class="form-group">
                    <label>Role</label>
                    <select id="role" name="role">
                        <option value="user">Collector (User)</option>
                        <option value="manager">Manager</option>
                        <option value="admin">Admin</option>
                    </select>
                </div>
                
                <button type="submit" class="btn-friendly" style="background:var(--accent); color:white; width:100%; margin-top:10px;">Save Changes</button>
            </form>
        </div>
    </div>

    <div class="modal-overlay" id="confirmModal">
        <div class="modal-card small">
            <div class="modal-header-icon delete-icon">
                <i class="fas fa-trash-alt"></i>
            </div>
            <h3>Delete User?</h3>
            <p>Are you sure you want to move this user to the Recycle Bin?</p>
            <div class="btn-group">
                <button class="btn-friendly" style="background:var(--border-color); color:var(--text-main);" onclick="closeModal('confirmModal')">Cancel</button>
                <button class="btn-friendly" id="confirmBtnAction" style="background:#ef4444; color:white;">Delete</button>
            </div>
        </div>
    </div>

    <div class="modal-overlay" id="alertModal">
        <div class="modal-card small">
            <div class="modal-header-icon success-icon" id="alertIcon">
                <i class="fas fa-check"></i>
            </div>
            <h3 id="alertTitle">Success!</h3>
            <p id="alertMessage">Action completed successfully.</p>
            <button class="btn-friendly" style="background:var(--text-main); color:var(--bg-body); width:100%;" onclick="closeModal('alertModal'); location.reload();">Okay</button>
        </div>
    </div>

    <script>
        // === THEME & NOTIFICATION LOGIC ===
        document.addEventListener('DOMContentLoaded', () => {
            // Theme Toggle
            const themeToggleBtn = document.getElementById('themeToggle');
            const themeIcon = themeToggleBtn.querySelector('i');
            const savedTheme = localStorage.getItem('adminTheme');
            if (savedTheme === 'dark') {
                document.documentElement.setAttribute('data-theme', 'dark');
                themeIcon.classList.replace('fa-moon', 'fa-sun');
            }

            themeToggleBtn.addEventListener('click', () => {
                const currentTheme = document.documentElement.getAttribute('data-theme');
                if (currentTheme === 'dark') {
                    document.documentElement.removeAttribute('data-theme');
                    localStorage.setItem('adminTheme', 'light');
                    themeIcon.classList.replace('fa-sun', 'fa-moon');
                } else {
                    document.documentElement.setAttribute('data-theme', 'dark');
                    localStorage.setItem('adminTheme', 'dark');
                    themeIcon.classList.replace('fa-moon', 'fa-sun');
                }
            });

            // Notifications
            const notifBtn = document.getElementById('adminNotifBtn');
            const notifDropdown = document.getElementById('adminNotifDropdown');
            const notifBadge = document.getElementById('adminNotifBadge');
            const notifList = document.getElementById('adminNotifList');
            const markAllBtn = document.getElementById('adminMarkAllRead');

            if(notifBtn) {
                notifBtn.addEventListener('click', (e) => { e.stopPropagation(); notifDropdown.classList.toggle('active'); });
                function fetchNotifications() {
                    fetch('fetch_notifications.php').then(res => res.json()).then(data => {
                        if (data.status === 'success') {
                            if (data.unread_count > 0) { notifBadge.innerText = data.unread_count; notifBadge.style.display = 'flex'; }
                            else { notifBadge.style.display = 'none'; }
                            notifList.innerHTML = '';
                            if (data.notifications.length === 0) notifList.innerHTML = '<li class="no-notif">No new notifications</li>';
                            else {
                                data.notifications.forEach(notif => {
                                    const li = document.createElement('li');
                                    li.className = `notif-item ${notif.is_read == 0 ? 'unread' : ''}`;
                                    li.innerHTML = `<div class="notif-msg">${notif.message}</div><div class="notif-time">${notif.created_at}</div><button class="btn-notif-close">×</button>`;
                                    li.addEventListener('click', () => { fetch('mark_as_read.php', { method: 'POST', body: new FormData().append('id', notif.id) }).then(() => fetchNotifications()); });
                                    notifList.appendChild(li);
                                });
                            }
                        }
                    });
                }
                if (markAllBtn) markAllBtn.addEventListener('click', (e) => { e.stopPropagation(); fetch('mark_all_as_read.php', { method: 'POST' }).then(() => fetchNotifications()); });
                window.addEventListener('click', () => { if (notifDropdown.classList.contains('active')) notifDropdown.classList.remove('active'); });
                fetchNotifications();
                setInterval(fetchNotifications, 30000);
            }
        });

        // --- MODAL & ALERT FUNCTIONS ---
        let deleteCallback = null;

        function closeModal(id) {
            document.getElementById(id).classList.remove('active');
        }

        function showAlert(title, msg, type, reload = false) {
            document.getElementById('alertTitle').innerText = title;
            document.getElementById('alertMessage').innerText = msg;
            
            const icon = document.getElementById('alertIcon');
            if (type === 'success') {
                icon.className = 'modal-header-icon success-icon';
                icon.innerHTML = '<i class="fas fa-check"></i>';
            } else {
                icon.className = 'modal-header-icon delete-icon';
                icon.innerHTML = '<i class="fas fa-exclamation-triangle"></i>';
            }
            
            const btn = document.querySelector('#alertModal button');
            btn.onclick = function() {
                closeModal('alertModal');
                if (reload) location.reload();
            };
            
            document.getElementById('alertModal').classList.add('active');
        }

        function confirmDelete(id) {
            deleteCallback = () => performDelete(id);
            document.getElementById('confirmModal').classList.add('active');
        }

        document.getElementById('confirmBtnAction').addEventListener('click', () => {
            if (deleteCallback) deleteCallback();
            closeModal('confirmModal');
        });

        // --- USER ACTIONS ---
        function openAddModal() {
            document.getElementById('userForm').reset();
            document.getElementById('userId').value = '';
            document.getElementById('actionType').value = 'add';
            document.getElementById('modalTitle').textContent = 'Add New User';
            document.getElementById('userModal').classList.add('active');
        }

        function editUser(btn) {
            const row = btn.closest('tr');
            document.getElementById('userId').value = row.dataset.id;
            document.getElementById('username').value = row.dataset.username;
            document.getElementById('email').value = row.dataset.email;
            document.getElementById('role').value = row.dataset.role || 'user';
            
            document.getElementById('actionType').value = 'update';
            document.getElementById('modalTitle').textContent = 'Edit User';
            document.getElementById('userModal').classList.add('active');
        }

        document.getElementById('userForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const action = document.getElementById('actionType').value;
            
            try {
                const res = await fetch(`manage_user.php?action=${action}`, { method: 'POST', body: formData });
                const data = await res.json();
                
                if(data.success) {
                    closeModal('userModal');
                    showAlert('Success!', 'User saved successfully.', 'success', true);
                } else {
                    showAlert('Error', data.message, 'error');
                }
            } catch (error) {
                showAlert('Error', 'An error occurred processing your request.', 'error');
            }
        });

        async function performDelete(id) {
            const formData = new FormData();
            formData.append('id', id);
            
            try {
                const res = await fetch('manage_user.php?action=delete', { method: 'POST', body: formData });
                const data = await res.json();
                
                if(data.success) {
                    showAlert('Deleted!', 'User moved to Recycle Bin.', 'success', true);
                } else {
                    showAlert('Error', data.message, 'error');
                }
            } catch (error) {
                showAlert('Error', 'An error occurred.', 'error');
            }
        }

        document.getElementById('userSearch').addEventListener('keyup', function() {
            const val = this.value.toLowerCase();
            document.querySelectorAll('#usersTable tbody tr').forEach(row => {
                const text = row.innerText.toLowerCase();
                row.style.display = text.includes(val) ? '' : 'none';
            });
        });
    </script>
</body>
</html>