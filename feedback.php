<?php
session_start();
include 'config.php';

// Security Check
if (!isset($_SESSION['username']) || !isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    header("Location: index.php");
    exit();
}

// --- SEARCH LOGIC ---
$search = $_GET['search'] ?? '';
$search_sql_inq = "";
$search_sql_rate = "";

if (!empty($search)) {
    $s = mysqli_real_escape_string($conn, $search);
    // Filter for Inquiries
    $search_sql_inq = "AND (username LIKE '%$s%' OR email LIKE '%$s%' OR message LIKE '%$s%')";
    
    // Filter for Ratings
    $search_sql_rate = "WHERE (u.username LIKE '%$s%' OR s.name LIKE '%$s%' OR r.review LIKE '%$s%')";
}

// 1. Fetch Inquiries (EXCLUDING Copy Requests)
$inquiries = [];
$sql_inq = "SELECT * FROM inquiries WHERE message NOT LIKE '%requesting a copy%' $search_sql_inq ORDER BY created_at DESC";
if ($res_inq = mysqli_query($conn, $sql_inq)) {
    while ($row = mysqli_fetch_assoc($res_inq)) {
        $inquiries[] = $row;
    }
}

// 2. Fetch Ratings
$ratings = [];
$sql_rate = "SELECT r.*, u.username, s.name as service_name 
             FROM ratings r 
             LEFT JOIN users u ON r.user_id = u.id 
             LEFT JOIN services s ON r.service_id = s.id 
             $search_sql_rate
             ORDER BY r.created_at DESC";
             
if ($res_rate = mysqli_query($conn, $sql_rate)) {
    while ($row = mysqli_fetch_assoc($res_rate)) {
        $ratings[] = $row;
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
    <title>Message & Feedback | ManCave Admin</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Nunito+Sans:wght@400;600;700;800&family=Playfair+Display:wght@600;700&family=Pacifico&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
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

        /* === SPECIFIC TO FEEDBACK === */
        
        /* Controls Bar */
        .controls-bar { margin-bottom: 25px; }
        .search-wrapper { position: relative; width: 100%; max-width: 400px; }
        .search-wrapper input { 
            width: 100%; padding: 12px 15px 12px 45px; border-radius: 50px; 
            border: 1px solid var(--border-color); outline: none; 
            background: var(--input-bg); color: var(--text-main); font-family: var(--font-main);
        }
        .search-wrapper i { position: absolute; left: 18px; top: 50%; transform: translateY(-50%); color: var(--text-muted); }

        /* Tabs */
        .tabs { margin-bottom: 30px; display: flex; gap: 10px; flex-wrap: wrap; border-bottom: 2px solid var(--border-color); padding-bottom: 5px; }
        .tab-btn { 
            background: none; border: none; padding: 12px 20px; 
            font-size: 1rem; font-weight: 700; color: var(--text-muted); 
            cursor: pointer; transition: 0.3s; border-bottom: 3px solid transparent; margin-bottom: -7px;
            display: flex; align-items: center; gap: 8px; font-family: var(--font-main);
        }
        .tab-btn:hover { color: var(--text-main); }
        .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }
        .tab-pane { display: none; animation: fadeIn 0.3s ease; }
        .tab-pane.active { display: block; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

        /* Tables */
        .card { background: var(--card-bg); border-radius: var(--radius-soft); box-shadow: 0 5px 15px var(--shadow-color); padding: 30px; border: 1px solid var(--border-color); }
        .card-header h3 { color: var(--text-main); font-family: var(--font-head); margin-bottom: 20px; font-size: 1.3rem; margin-top: 0; }
        .table-responsive { overflow-x: auto; }
        .styled-table { width: 100%; border-collapse: collapse; }
        .styled-table th {
            text-align: left; padding: 18px 25px; background: var(--bg-body);
            color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px;
            border-bottom: 1px solid var(--border-color); font-weight: 700;
        }
        .styled-table td { padding: 18px 25px; border-bottom: 1px solid var(--border-color); color: var(--text-main); vertical-align: middle; }
        .styled-table tr:hover { background: rgba(0,0,0,0.02); }

        .user-cell strong { display: block; font-size: 0.95rem; color: var(--text-main); }
        .user-cell small { color: var(--text-muted); }
        
        .msg-preview { max-width: 350px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: var(--text-muted); font-size: 0.9rem; }
        .unread-row { background-color: rgba(205, 133, 63, 0.05); }
        .unread-row td { font-weight: 600; }

        /* Status Badges */
        .status-badge { padding: 5px 12px; border-radius: 50px; font-size: 0.75rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; display: inline-block; }
        .status-pending { background: rgba(245, 158, 11, 0.1); color: var(--orange); }
        .status-approved { background: rgba(209, 213, 219, 0.2); color: var(--text-muted); } /* Read */
        .status-completed { background: rgba(16, 185, 129, 0.1); color: var(--green); } /* Replied */

        /* Stars */
        .stars { color: var(--orange); font-size: 0.85rem; letter-spacing: 2px; }
        .star-empty { color: var(--border-color); }

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
        
        .modal-card.large { width: 650px; max-width: 95%; border-radius: 16px; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 20px 60px rgba(0,0,0,0.2); transform: translateY(20px); transition: 0.3s; }
        .modal-overlay.active .modal-card.large { transform: translateY(0); }
        
        .modal-card.small { width: 400px; max-width: 90%; border-radius: 16px; padding: 35px; text-align: center; box-shadow: 0 20px 60px rgba(0,0,0,0.2); transform: translateY(20px); transition: 0.3s; }
        .modal-overlay.active .modal-card.small { transform: translateY(0); }
        
        .modal-header { display: flex; justify-content: space-between; align-items: center; padding: 20px 30px; border-bottom: 1px solid var(--border-color); background: var(--bg-body); }
        .modal-header h3 { font-family: var(--font-head); font-size: 1.5rem; color: var(--text-main); margin: 0; }
        .modal-body { padding: 30px; overflow-y: auto; max-height: 70vh; }
        
        .modal-header-icon { width: 70px; height: 70px; border-radius: 50%; margin: 0 auto 20px; display: flex; align-items: center; justify-content: center; font-size: 2rem; }
        .delete-icon { background: rgba(239, 68, 68, 0.1); color: var(--red); }
        .success-icon { background: rgba(16, 185, 129, 0.1); color: var(--green); }
        
        .modal-card.small h3 { font-family: var(--font-head); font-size: 1.5rem; margin-bottom: 10px; color: var(--text-main); }
        .modal-card.small p { color: var(--text-muted); }

        .inquiry-box { background: var(--bg-body); border: 1px solid var(--border-color); border-radius: 8px; padding: 20px; margin-bottom: 25px; color: var(--text-main); font-size: 0.95rem; }
        
        .reply-section label { display: block; margin-bottom: 8px; font-weight: 700; font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; }
        .reply-section input, .reply-section textarea { 
            width: 100%; padding: 12px 15px; border: 1px solid var(--border-color); 
            border-radius: 8px; background: var(--input-bg); color: var(--text-main); 
            font-size: 0.95rem; outline: none; transition: 0.3s; font-family: var(--font-main); margin-bottom: 15px;
        }
        .reply-section input:focus, .reply-section textarea:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(205, 133, 63, 0.1); }

        .btn-group { display: flex; gap: 10px; justify-content: center; margin-top: 20px; }
        .btn-friendly { padding: 12px 25px; border-radius: 8px; font-weight: 700; border: none; cursor: pointer; transition: 0.2s; font-size: 0.95rem; font-family: var(--font-main); }
        .btn-friendly:hover { transform: translateY(-2px); opacity: 0.9; }
        .btn-close-modal { background: none; border: none; font-size: 2rem; line-height: 1; cursor: pointer; color: var(--text-muted); }
        .btn-close-modal:hover { color: var(--red); }

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
                <li><a href="users.php"><i class="fas fa-users"></i> <span>Customers & Staff</span></a></li>
                <li class="active"><a href="feedback.php"><i class="fas fa-comments"></i> <span>Message & Feedback</span></a></li>
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
                <h1>Message & Feedback Center</h1>
                <p>Manage customer inquiries and service reviews.</p>
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
            <form method="GET" class="search-wrapper">
                <i class="fas fa-search"></i>
                <input type="text" name="search" value="<?php echo htmlspecialchars($search); ?>" placeholder="Search messages, emails, or reviews...">
            </form>
        </div>

        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('inquiries', this)"><i class="fas fa-envelope"></i> Message Inquiries</button>
            <button class="tab-btn" onclick="switchTab('ratings', this)"><i class="fas fa-star"></i> Service Ratings</button>
        </div>

        <div id="inquiries" class="tab-pane active">
            <div class="card table-card">
                <div class="card-header"><h3>Customer Messages</h3></div>
                <div class="table-responsive">
                    <table class="styled-table">
                        <thead>
                            <tr>
                                <th style="width: 20%;">Username</th>
                                <th style="width: 20%;">Email Address</th>
                                <th style="width: 20%;">Message Preview</th>
                                <th style="width: 15%;">Status</th>
                                <th style="width: 15%;">Date</th>
                                <th style="width: 10%; text-align:right;">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if(empty($inquiries)): ?>
                                <tr><td colspan="6" class="text-center" style="padding:50px; color:var(--text-muted);">No general inquiries found.</td></tr>
                            <?php else: ?>
                                <?php foreach ($inquiries as $inq): 
                                    $isUnread = ($inq['status'] !== 'read' && $inq['status'] !== 'replied');
                                    // Map statuses to badge classes
                                    $statusClass = 'status-approved'; // Default Read
                                    if ($inq['status'] == 'replied') $statusClass = 'status-completed';
                                    if ($isUnread) $statusClass = 'status-pending';
                                    
                                    $statusLabel = ($inq['status'] == 'replied') ? 'Replied' : ($isUnread ? 'Unread' : 'Read');
                                ?>
                                <tr class="<?= $isUnread ? 'unread-row' : '' ?>">
                                    <td>
                                        <div class="user-cell">
                                            <strong><?= htmlspecialchars($inq['username']) ?></strong>
                                        </div>
                                    </td>
                                    <td>
                                        <div class="user-cell">
                                            <small><?= htmlspecialchars($inq['email']) ?></small>
                                        </div>
                                    </td>
                                    <td>
                                        <div class="msg-preview"><?= htmlspecialchars($inq['message']) ?></div>
                                    </td>
                                    <td><span class="status-badge <?= $statusClass ?>"><?= $statusLabel ?></span></td>
                                    <td><?= date('M d, Y', strtotime($inq['created_at'])) ?></td>
                                    <td style="text-align:right;">
                                        <div class="actions" style="justify-content: flex-end;">
                                            <button class="btn-icon edit" onclick="viewInquiry(<?= $inq['id'] ?>)" title="View & Reply">
                                                <i class="fas fa-envelope-open-text"></i>
                                            </button>
                                            <button class="btn-icon delete" onclick="confirmAction('inquiry', <?= $inq['id'] ?>)" title="Move to Trash">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="ratings" class="tab-pane">
            <div class="card table-card">
                <div class="card-header"><h3>Service Reviews</h3></div>
                <div class="table-responsive">
                    <table class="styled-table">
                        <thead>
                            <tr>
                                <th>Customer</th>
                                <th>Service Rated</th>
                                <th>Rating</th>
                                <th>Review</th>
                                <th style="text-align:left;">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if(empty($ratings)): ?>
                                <tr><td colspan="5" class="text-center" style="padding:50px; color:var(--text-muted);">No ratings yet.</td></tr>
                            <?php else: ?>
                                <?php foreach ($ratings as $rate): ?>
                                <tr>
                                    <td><strong><?= htmlspecialchars($rate['username'] ?? 'Guest') ?></strong></td>
                                    <td><?= htmlspecialchars($rate['service_name'] ?? 'General/Artwork') ?></td>
                                    <td>
                                        <div class="stars">
                                            <?php for($i=1; $i<=5; $i++): ?>
                                                <i class="fas fa-star <?= $i <= $rate['rating'] ? '' : 'star-empty' ?>"></i>
                                            <?php endfor; ?>
                                        </div>
                                    </td>
                                    <td><div class="msg-preview"><?= htmlspecialchars($rate['review']) ?></div></td>
                                    <td style="text-align:left;">
                                        <button class="btn-icon delete" onclick="confirmAction('rating', <?= $rate['id'] ?>)" title="Delete Review">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

    </main>

    <div class="modal-overlay" id="inquiryModal">
        <div class="modal-card large">
            <div class="modal-header">
                <h3>Inquiry Details</h3>
                <button onclick="closeModal('inquiryModal')" class="btn-close-modal">&times;</button>
            </div>
            <div class="modal-body">
                <div id="inquiryContent" class="inquiry-box">
                    <p style="text-align:center; color:var(--text-muted);">Loading details...</p>
                </div>
                <div class="reply-section">
                    <h4 style="margin: 0 0 15px 0; color: var(--accent); font-size: 0.95rem; text-transform: uppercase; letter-spacing: 1px;">Reply to Customer</h4>
                    <form id="replyForm">
                        <input type="hidden" id="replyId" name="id">
                        <div style="margin-bottom: 15px;">
                            <label>Subject</label>
                            <input type="text" name="subject" value="Re: Your Inquiry - ManCave Gallery" required>
                        </div>
                        <div style="margin-bottom: 20px;">
                            <label>Message</label>
                            <textarea name="message" rows="5" placeholder="Type your reply here..." required></textarea>
                        </div>
                        <button type="submit" class="btn-friendly" style="width:100%; background:var(--accent); color:white;">Send Reply <i class="fas fa-paper-plane"></i></button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <div class="modal-overlay" id="confirmModal">
        <div class="modal-card small">
            <div class="modal-header-icon delete-icon">
                <i class="fas fa-trash-alt"></i>
            </div>
            <h3 id="confirmTitle">Delete Item?</h3>
            <p id="confirmText">Are you sure you want to move this to the recycle bin?</p>
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

            if (notifBtn) {
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
                                            <button class="btn-notif-close" title="Delete">×</button>
                                        `;
                                        li.addEventListener('click', (e) => {
                                            if (e.target.classList.contains('btn-notif-close')) return;
                                            const formData = new FormData();
                                            formData.append('id', notif.id);
                                            fetch('mark_as_read.php', { method: 'POST', body: formData }).then(() => fetchNotifications());
                                        });
                                        li.querySelector('.btn-notif-close').addEventListener('click', (e) => {
                                            e.stopPropagation();
                                            if (!confirm('Delete notification?')) return;
                                            const formData = new FormData();
                                            formData.append('id', notif.id);
                                            fetch('delete_notifications.php', { method: 'POST', body: formData }).then(res => res.json()).then(d => { if (d.status === 'success') fetchNotifications(); });
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

        // --- TABS ---
        function switchTab(tabId, btn) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        }

        // --- MODAL LOGIC ---
        let actionCallback = null;

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

        function confirmAction(type, id) {
            if (type === 'inquiry') {
                document.getElementById('confirmTitle').innerText = 'Trash Inquiry?';
                document.getElementById('confirmText').innerText = 'This message will be moved to the recycle bin.';
                actionCallback = () => deleteInquiry(id);
            } else if (type === 'rating') {
                document.getElementById('confirmTitle').innerText = 'Delete Review?';
                document.getElementById('confirmText').innerText = 'This will move the review to the recycle bin.';
                actionCallback = () => deleteRating(id);
            }
            document.getElementById('confirmModal').classList.add('active');
        }

        document.getElementById('confirmBtnAction').addEventListener('click', () => {
            if (actionCallback) actionCallback();
            closeModal('confirmModal');
        });

        // --- INQUIRY LOGIC ---
        function viewInquiry(id) {
            document.getElementById('inquiryModal').classList.add('active');
            document.getElementById('inquiryContent').innerHTML = '<p style="text-align:center; color:var(--text-muted);">Loading details...</p>';
            document.getElementById('replyId').value = id;

            fetch(`get_inquiry.php?id=${id}`)
                .then(res => res.json())
                .then(data => {
                    if (data.error) {
                        document.getElementById('inquiryContent').innerHTML = `<p style="color:red;">${data.error}</p>`;
                    } else {
                        document.getElementById('inquiryContent').innerHTML = `
                            <div style="display:flex; justify-content:space-between; border-bottom:1px solid var(--border-color); padding-bottom:10px; margin-bottom:10px;">
                                <div>
                                    <span style="display:block; font-size:0.85rem; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.5px;">From</span>
                                    <strong style="font-size:1.1rem; color:var(--text-main);">${data.username}</strong>
                                    <div style="color:var(--text-muted); font-size:0.9rem;">${data.email}</div>
                                </div>
                                <div style="text-align:right;">
                                    <span style="display:block; font-size:0.85rem; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.5px;">Date</span>
                                    <div style="font-weight:600; color:var(--text-muted);">${data.created_at}</div>
                                </div>
                            </div>
                            <div style="margin-bottom:10px;">
                                <span style="font-size:0.85rem; color:var(--text-muted); font-weight:700;">Contact:</span> 
                                <span style="color:var(--text-main);">${data.mobile}</span>
                            </div>
                            <div style="margin-top:15px;">
                                <span style="display:block; font-size:0.85rem; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.5px; margin-bottom:5px;">Message</span>
                                <p style="line-height:1.6; color:var(--text-main); white-space: pre-wrap; margin:0;">${data.message}</p>
                            </div>
                        `;
                    }
                });
        }

        // Reply Form
        document.getElementById('replyForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const btn = e.target.querySelector('button');
            const originalText = btn.innerHTML;
            btn.disabled = true; btn.innerHTML = 'Sending...';

            try {
                const res = await fetch('reply_inquiry.php', { method: 'POST', body: formData });
                const text = await res.text();
                if (text.trim() === 'success') {
                    closeModal('inquiryModal');
                    showAlert('Sent!', 'Reply sent successfully!', 'success', true);
                } else {
                    showAlert('Error', 'Error sending email. Please try again.', 'error');
                }
            } catch (err) {
                showAlert('Error', 'Request failed.', 'error');
            } finally {
                btn.disabled = false; btn.innerHTML = originalText;
            }
        });

        // Delete Functions
        function deleteInquiry(id) {
            const formData = new FormData();
            formData.append('id', id);
            fetch('delete_inquiry.php', { method: 'POST', body: formData })
                .then(res => res.json())
                .then(data => {
                    if (data.status === 'success') showAlert('Deleted!', 'Inquiry moved to trash.', 'success', true);
                    else showAlert('Error', data.message, 'error');
                });
        }

        function deleteRating(id) {
            const formData = new FormData();
            formData.append('id', id);
            formData.append('action', 'delete_rating');
            fetch('manage_feedback.php', { method: 'POST', body: formData })
                .then(res => res.json())
                .then(data => {
                    if (data.success) showAlert('Deleted!', 'Review moved to trash.', 'success', true);
                    else showAlert('Error', 'Error deleting rating.', 'error');
                });
        }
    </script>
</body>
</html>