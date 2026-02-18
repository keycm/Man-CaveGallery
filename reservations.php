<?php
session_start();
include 'config.php';

// Security Check
if (!isset($_SESSION['username']) || !isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    header("Location: index.php");
    exit();
}

// 1. Fetch Reservations
$reservations = [];
$sql = "SELECT b.*, 
               u.email as user_email, 
               u.username as user_username,
               a.image_path 
        FROM bookings b
        LEFT JOIN users u ON b.user_id = u.id
        LEFT JOIN artworks a ON b.artwork_id = a.id
        WHERE b.deleted_at IS NULL
        ORDER BY b.created_at DESC";

if ($res = mysqli_query($conn, $sql)) {
    while ($row = mysqli_fetch_assoc($res)) {
        $reservations[] = $row;
    }
}

// 2. Fetch Copy Requests
$copy_requests = [];
$sql_copy = "SELECT * FROM inquiries WHERE message LIKE '%requesting a copy%' ORDER BY created_at DESC";
if ($res_copy = mysqli_query($conn, $sql_copy)) {
    while ($row = mysqli_fetch_assoc($res_copy)) {
        $copy_requests[] = $row;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Appointments | ManCave Admin</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Nunito+Sans:wght@400;600;700;800&family=Playfair+Display:wght@600;700&family=Pacifico&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src='https://cdn.jsdelivr.net/npm/fullcalendar@6.1.8/index.global.min.js'></script>

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

        /* === SPECIFIC TO RESERVATIONS === */
        
        /* Tabs */
        .tabs-container { display: flex; gap: 20px; margin-bottom: 25px; border-bottom: 2px solid var(--border-color); padding-bottom: 5px; }
        .tab-btn {
            background: none; border: none; padding: 12px 20px;
            font-size: 1rem; font-weight: 700; color: var(--text-muted);
            cursor: pointer; position: relative; transition: 0.3s;
            border-bottom: 3px solid transparent; margin-bottom: -7px; font-family: var(--font-main);
            display: flex; align-items: center; gap: 8px;
        }
        .tab-btn:hover { color: var(--text-main); }
        .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }

        .view-pane { display: none; animation: fadeIn 0.3s ease; }
        .view-pane.active { display: block; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

        /* Controls */
        .controls-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; flex-wrap: wrap; gap: 15px; }
        .search-wrapper { position: relative; width: 100%; max-width: 350px; }
        .search-wrapper input { 
            width: 100%; padding: 12px 15px 12px 45px; border-radius: 50px; 
            border: 1px solid var(--border-color); outline: none; 
            background: var(--input-bg); color: var(--text-main); font-family: var(--font-main);
        }
        .search-wrapper i { position: absolute; left: 18px; top: 50%; transform: translateY(-50%); color: var(--text-muted); }

        .filter-group { background: var(--card-bg); padding: 5px; border-radius: 50px; border: 1px solid var(--border-color); display: flex; }
        .filter-btn { 
            border: none; background: none; padding: 8px 20px; border-radius: 50px; 
            font-size: 0.85rem; font-weight: 700; color: var(--text-muted); cursor: pointer; transition: 0.3s; font-family: var(--font-main);
        }
        .filter-btn.active { background: var(--accent); color: #ffffff; }

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

        .art-cell { display: flex; align-items: center; gap: 15px; }
        .art-thumb { width: 50px; height: 50px; border-radius: 8px; object-fit: cover; border: 1px solid var(--border-color); }
        .info-sub { font-size: 0.85rem; color: var(--text-muted); display: block; margin-top: 4px; cursor: pointer; transition: 0.2s; }
        .info-sub:hover { color: var(--accent); text-decoration: underline; }

        /* Status Badges */
        .status-badge { padding: 6px 12px; border-radius: 50px; font-size: 0.75rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; display: inline-block; }
        .status-pending { background: rgba(245, 158, 11, 0.1); color: var(--orange); }
        .status-approved { background: rgba(59, 130, 246, 0.1); color: var(--blue); }
        .status-completed { background: rgba(16, 185, 129, 0.1); color: var(--green); }
        .status-rejected, .status-cancelled { background: rgba(239, 68, 68, 0.1); color: var(--red); }
        .status-inquiry { background: rgba(59, 130, 246, 0.1); color: var(--blue); }

        /* Calendar */
        .fc { background: var(--card-bg); color: var(--text-main); padding: 25px; border-radius: var(--radius-soft); box-shadow: 0 5px 15px var(--shadow-color); border: 1px solid var(--border-color); }
        .fc-toolbar-title { font-family: var(--font-head); font-size: 1.5rem !important; color: var(--text-main); }
        .fc-button-primary { background-color: var(--accent) !important; border: none !important; border-radius: 6px !important; }
        .fc-theme-standard td, .fc-theme-standard th { border-color: var(--border-color) !important; }
        .fc-daygrid-day-number { color: var(--text-main); text-decoration: none; }
        .fc-col-header-cell-cushion { color: var(--text-muted); text-decoration: none; }

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

        /* Modals */
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; opacity: 0; visibility: hidden; transition: 0.3s; z-index: 2000; }
        .modal-overlay.active { opacity: 1; visibility: visible; }
        
        .modal-card { background: var(--card-bg); border: 1px solid var(--border-color); color: var(--text-main); }
        .modal-card.small { width: 450px; max-width: 90%; border-radius: 16px; padding: 35px; text-align: center; box-shadow: 0 20px 60px rgba(0,0,0,0.2); transform: translateY(20px); transition: 0.3s; }
        .modal-overlay.active .modal-card.small { transform: translateY(0); }
        
        .modal-card.large { width: 600px; max-width: 95%; border-radius: 16px; overflow: hidden; box-shadow: 0 20px 60px rgba(0,0,0,0.2); transform: translateY(20px); transition: 0.3s; display: flex; flex-direction: column; }
        .modal-overlay.active .modal-card.large { transform: translateY(0); }

        .modal-header-icon { width: 70px; height: 70px; border-radius: 50%; margin: 0 auto 20px; display: flex; align-items: center; justify-content: center; font-size: 2rem; }
        .delete-icon { background: rgba(239, 68, 68, 0.1); color: #ef4444; }
        .success-icon { background: rgba(16, 185, 129, 0.1); color: #10b981; }
        .question-icon { background: rgba(205, 133, 63, 0.1); color: #cd853f; }
        
        .modal-card h3 { font-family: var(--font-head); font-size: 1.5rem; margin-bottom: 10px; color: var(--text-main); }
        .modal-card p, .modal-card label { color: var(--text-muted); }
        .modal-card input, .modal-card textarea { 
            background: var(--input-bg); border: 1px solid var(--border-color); color: var(--text-main); 
            width: 100%; padding: 12px; border-radius: 8px; font-size: 0.95rem; outline: none; margin-bottom: 15px; font-family: var(--font-main); 
        }
        .modal-card input:focus, .modal-card textarea:focus { border-color: var(--accent); }
        
        .modal-header { padding: 20px 30px; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; background: var(--bg-body); }
        .modal-body { padding: 30px; }

        .btn-group { display: flex; gap: 15px; justify-content: center; margin-top: 20px; }
        .btn-friendly { padding: 12px 25px; border-radius: 8px; font-weight: 700; border: none; cursor: pointer; transition: 0.2s; font-size: 0.95rem; font-family: var(--font-main); }
        .btn-friendly:hover { transform: translateY(-2px); opacity: 0.9; }

        @media (max-width: 1024px) {
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
                <li class="active"><a href="reservations.php"><i class="fas fa-calendar-check"></i> <span>Appointments</span></a></li>
                <li><a href="content.php"><i class="fas fa-layer-group"></i> <span>Website Content</span></a></li>
                <li><a href="manage_hero.php"><i class="fas fa-images"></i> <span>Manage Slider</span></a></li>
                <li><a href="manage_news.php"><i class="fas fa-newspaper"></i> <span>Gallery Updates</span></a></li>
                <li><a href="manage_team.php"><i class="fas fa-user-tie"></i> <span>Manage Artists</span></a></li>
                <li><a href="manage_about_artists.php"><i class="fas fa-users-cog"></i> <span>About: Meet Artists</span></a></li>
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
                <h1>Appointments & Requests</h1>
                <p>Manage viewings, schedule, and artwork requests.</p>
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

        <div class="tabs-container">
            <button class="tab-btn active" onclick="switchView('list')"><i class="fas fa-list-ul"></i> List View</button>
            <button class="tab-btn" onclick="switchView('copyRequests')"><i class="fas fa-clone"></i> Requests</button>
            <button class="tab-btn" onclick="switchView('calendar')"><i class="far fa-calendar-alt"></i> Calendar</button>
        </div>

        <div id="listView" class="view-pane active">
            <div class="controls-bar">
                <div class="search-wrapper">
                    <i class="fas fa-search"></i>
                    <input type="text" id="reqSearch" placeholder="Search by name, artwork, or date...">
                </div>
                <div class="filter-group">
                    <button class="filter-btn active" onclick="filterTable('all', this)">All</button>
                    <button class="filter-btn" onclick="filterTable('pending', this)">Pending</button>
                    <button class="filter-btn" onclick="filterTable('approved', this)">Approved</button>
                    <button class="filter-btn" onclick="filterTable('completed', this)">Completed</button>
                </div>
            </div>

            <div class="card table-card">
                <div class="table-responsive">
                    <table class="styled-table" id="resTable">
                        <thead>
                            <tr>
                                <th>Booking Detail</th>
                                <th>Customer Info</th>
                                <th>Date</th>
                                <th>Status</th>
                                <th style="text-align:right;">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($reservations)): ?>
                                <tr><td colspan="5" class="text-center" style="padding:40px; color:var(--text-muted);">No appointments found.</td></tr>
                            <?php else: ?>
                                <?php foreach ($reservations as $r): 
                                    $status = strtolower($r['status']); 
                                    $img = !empty($r['image_path']) ? 'uploads/'.$r['image_path'] : 'https://placehold.co/50x50/eee/999?text=Art';
                                    $title = !empty($r['service']) ? $r['service'] : 'General Appointment';
                                    $name = !empty($r['full_name']) ? $r['full_name'] : ($r['user_username'] ?? 'Guest');
                                    $contact = !empty($r['phone_number']) ? $r['phone_number'] : 'N/A';
                                    $email = !empty($r['user_email']) ? $r['user_email'] : 'N/A';
                                    $validIdPath = !empty($r['valid_id_image']) ? 'uploads/' . $r['valid_id_image'] : '';

                                    $jsonData = htmlspecialchars(json_encode([
                                        'title' => $title,
                                        'name' => $name,
                                        'contact' => $contact,
                                        'email' => $email,
                                        'date' => date('F d, Y', strtotime($r['preferred_date'])),
                                        'status' => ucfirst($status),
                                        'request' => $r['special_requests'],
                                        'valid_id' => $validIdPath
                                    ]));
                                ?>
                                <tr data-status="<?= $status ?>">
                                    <td>
                                        <div class="art-cell">
                                            <img src="<?= htmlspecialchars($img) ?>" class="art-thumb" alt="Thumb">
                                            <div>
                                                <strong style="color:var(--text-main);"><?= htmlspecialchars($title) ?></strong>
                                                <span class="info-sub" onclick='viewBooking(<?= $jsonData ?>)' title="Click to view full details">
                                                    <?= htmlspecialchars(substr($r['special_requests'], 0, 30)) . (strlen($r['special_requests']) > 30 ? '...' : '') ?>
                                                </span>
                                            </div>
                                        </div>
                                    </td>
                                    <td>
                                        <strong style="color:var(--text-main);"><?= htmlspecialchars($name) ?></strong>
                                        <span class="info-sub"><i class="fas fa-phone" style="font-size:0.7rem;"></i> <?= htmlspecialchars($contact) ?></span>
                                        <span class="info-sub" style="font-size:0.75rem;"><?= htmlspecialchars($email) ?></span>
                                    </td>
                                    <td>
                                        <i class="far fa-calendar" style="color:var(--text-muted); margin-right:5px;"></i>
                                        <?= date('M d, Y', strtotime($r['preferred_date'])) ?>
                                    </td>
                                    <td>
                                        <span class="status-badge status-<?= $status ?>">
                                            <?= ucfirst($status) ?>
                                        </span>
                                    </td>
                                    <td style="text-align:right;">
                                        <div class="actions" style="display:flex; justify-content: flex-end; gap:5px;">
                                            <button class="icon-btn" style="width:32px; height:32px; font-size:0.9rem;" onclick='viewBooking(<?= $jsonData ?>)' title="View Details">
                                                <i class="fas fa-eye"></i>
                                            </button>

                                            <?php if ($status == 'pending'): ?>
                                                <button class="icon-btn" style="width:32px; height:32px; font-size:0.9rem; color:#10b981;" onclick="updateStatus(<?= $r['id'] ?>, 'approved', this)" title="Approve"><i class="fas fa-check"></i></button>
                                                <button class="icon-btn" style="width:32px; height:32px; font-size:0.9rem; color:#ef4444;" onclick="updateStatus(<?= $r['id'] ?>, 'rejected', this)" title="Reject"><i class="fas fa-times"></i></button>
                                            
                                            <?php elseif ($status == 'approved'): ?>
                                                <button class="icon-btn" style="width:32px; height:32px; font-size:0.9rem; color:#3b82f6;" onclick="updateStatus(<?= $r['id'] ?>, 'completed', this)" title="Mark Completed"><i class="fas fa-flag-checkered"></i></button>
                                            
                                            <?php elseif ($status == 'completed'): ?>
                                                <span style="font-size:0.8rem; color:var(--text-muted); font-weight:700; margin-right:5px; display:flex; align-items:center;">
                                                    <i class="fas fa-check-circle"></i> Done
                                                </span>
                                            <?php endif; ?>

                                            <button class="icon-btn" style="width:32px; height:32px; font-size:0.9rem; color:#ef4444;" onclick="updateStatus(<?= $r['id'] ?>, 'delete', this)" title="Move to Trash"><i class="far fa-trash-alt"></i></button>
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

        <div id="copyRequestsView" class="view-pane">
            <div class="controls-bar">
                <h3 style="margin:0; color:var(--text-main); font-family:var(--font-head);"><i class="fas fa-clone" style="color:var(--accent); margin-right:10px;"></i> User Requests</h3>
            </div>
            <div class="card table-card">
                <div class="table-responsive">
                    <table class="styled-table">
                        <thead>
                            <tr>
                                <th>Customer</th>
                                <th>Contact</th>
                                <th>Message / Request</th>
                                <th>Date Sent</th>
                                <th style="text-align:right;">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($copy_requests)): ?>
                                <tr><td colspan="5" class="text-center" style="padding:40px; color:var(--text-muted);">No copy requests found.</td></tr>
                            <?php else: ?>
                                <?php foreach ($copy_requests as $req): 
                                    $msg = $req['message'];
                                    $reqData = htmlspecialchars(json_encode([
                                        'title' => 'Copy Request',
                                        'name' => $req['username'],
                                        'contact' => $req['mobile'],
                                        'email' => $req['email'],
                                        'date' => date('F d, Y', strtotime($req['created_at'])),
                                        'status' => 'Inquiry',
                                        'request' => $msg
                                    ]));
                                ?>
                                <tr>
                                    <td>
                                        <strong style="color:var(--text-main);"><?= htmlspecialchars($req['username']) ?></strong>
                                        <div class="info-sub"><?= htmlspecialchars($req['email']) ?></div>
                                    </td>
                                    <td>
                                        <i class="fas fa-phone" style="font-size:0.75rem; color:var(--text-muted);"></i> 
                                        <?= htmlspecialchars($req['mobile']) ?>
                                    </td>
                                    <td>
                                        <div style="max-width:350px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; color:var(--text-main);">
                                            <?= htmlspecialchars($msg) ?>
                                        </div>
                                    </td>
                                    <td><?= date('M d, Y', strtotime($req['created_at'])) ?></td>
                                    <td style="text-align:right;">
                                        <div class="actions" style="display:flex; justify-content: flex-end; gap:5px;">
                                            <button class="icon-btn" style="width:32px; height:32px; font-size:0.9rem;" onclick='viewBooking(<?= $reqData ?>)' title="Read Full Message">
                                                <i class="fas fa-envelope-open-text"></i>
                                            </button>
                                            
                                            <button class="icon-btn" style="width:32px; height:32px; font-size:0.9rem; color:var(--accent);" onclick="openReplyModal(<?= $req['id'] ?>, '<?= htmlspecialchars($req['email']) ?>')" title="Reply via Email">
                                                <i class="fas fa-reply"></i>
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

        <div id="calendarView" class="view-pane">
            <div id="calendar"></div>
        </div>

    </main>

    <div id="viewModal" class="modal-overlay">
        <div class="modal-card small" style="text-align:left; width:550px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; border-bottom: 1px solid var(--border-color); padding-bottom: 15px;">
                <h3 style="margin: 0;">Details</h3>
                <button onclick="closeViewModal()" style="background: none; border: none; font-size: 2rem; line-height: 1; cursor: pointer; color: var(--text-muted);">&times;</button>
            </div>

            <div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; background: var(--bg-body); padding: 15px; border-radius: 8px;">
                    <strong id="view-title" style="color: var(--accent); font-size: 1.1rem;"></strong>
                    <span id="view-status" class="status-badge"></span>
                </div>

                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px;">
                    <div>
                        <span style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700; letter-spacing: 0.5px; display: block; margin-bottom: 4px;">Customer Name</span>
                        <div id="view-name" style="font-weight: 600; color:var(--text-main);"></div>
                    </div>
                    <div>
                        <span style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700; letter-spacing: 0.5px; display: block; margin-bottom: 4px;">Date</span>
                        <div id="view-date" style="font-weight: 600; color:var(--text-main);"></div>
                    </div>
                    <div>
                        <span style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700; letter-spacing: 0.5px; display: block; margin-bottom: 4px;">Contact</span>
                        <div id="view-contact" style="font-weight: 600; color:var(--text-main);"></div>
                    </div>
                    <div>
                        <span style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700; letter-spacing: 0.5px; display: block; margin-bottom: 4px;">Email</span>
                        <div id="view-email" style="font-weight: 600; color:var(--text-main);"></div>
                    </div>
                </div>

                <div style="margin-top: 20px;">
                    <span style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700; letter-spacing: 0.5px; display: block; margin-bottom: 8px;">Message / Request</span>
                    <div id="view-request" style="background: var(--bg-body); border: 1px solid var(--border-color); padding: 15px; border-radius: 8px; font-size: 0.95rem; line-height: 1.6; color: var(--text-main); min-height: 80px; word-wrap: break-word; white-space: pre-wrap;"></div>
                </div>

                <div id="view-id-container" style="margin-top: 20px; display:none;">
                    <span style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700; letter-spacing: 0.5px; display: block; margin-bottom: 8px;">Valid ID</span>
                    <a id="view-valid-id-link" href="#" target="_blank">
                        <img id="view-valid-id" src="" alt="Valid ID" style="max-width: 100%; height: auto; border-radius: 8px; border: 1px solid var(--border-color);">
                    </a>
                </div>
            </div>

            <div style="text-align: right; margin-top: 25px;">
                <button onclick="closeViewModal()" class="btn-friendly" style="background: var(--text-main); color: var(--bg-body);">Close Details</button>
            </div>
        </div>
    </div>

    <div class="modal-overlay" id="replyModal">
        <div class="modal-card large">
            <div class="modal-header">
                <h3>Reply to Inquiry</h3>
                <button onclick="closeModal('replyModal')" style="background:none; border:none; font-size:1.5rem; cursor:pointer; color:var(--text-muted);">&times;</button>
            </div>
            <div class="modal-body">
                <div class="reply-section">
                    <p style="color:var(--text-muted); font-size:0.9rem; margin-bottom:15px;">Replying to: <strong id="replyToEmail" style="color:var(--text-main);"></strong></p>
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
            <div class="modal-header-icon question-icon" id="confirmIcon">
                <i class="fas fa-question"></i>
            </div>
            <h3 id="confirmTitle">Confirm Action</h3>
            <p id="confirmText">Are you sure you want to proceed?</p>
            <div class="btn-group">
                <button class="btn-friendly" style="background:var(--border-color); color:var(--text-main);" onclick="closeModal('confirmModal')">Cancel</button>
                <button class="btn-friendly" id="confirmBtnAction" style="background:var(--accent); color:white;">Confirm</button>
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
        // --- VIEW SWITCHER ---
        function switchView(viewName) {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            event.currentTarget.classList.add('active');
            document.querySelectorAll('.view-pane').forEach(pane => pane.classList.remove('active'));
            document.getElementById(viewName + 'View').classList.add('active');
            if (viewName === 'calendar') setTimeout(renderCalendar, 100);
        }

        // --- FILTER & SEARCH ---
        function filterTable(status, btn) {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('#resTable tbody tr').forEach(row => {
                row.style.display = (status === 'all' || row.dataset.status === status) ? '' : 'none';
            });
        }

        document.getElementById('reqSearch').addEventListener('keyup', function() {
            const val = this.value.toLowerCase();
            document.querySelectorAll('#resTable tbody tr').forEach(row => {
                const text = row.innerText.toLowerCase();
                row.style.display = text.includes(val) ? '' : 'none';
            });
        });

        // --- MODAL HELPERS ---
        function closeModal(id) {
            document.getElementById(id).classList.remove('active');
        }

        // Friendly Alert
        function showAlert(title, msg, type) {
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
            document.getElementById('alertModal').classList.add('active');
        }

        // Friendly Confirm
        let confirmCallback = null;
        function showConfirm(title, msg, btnText, btnColor, callback) {
            document.getElementById('confirmTitle').innerText = title;
            document.getElementById('confirmText').innerText = msg;
            
            const btn = document.getElementById('confirmBtnAction');
            btn.innerText = btnText;
            btn.style.background = btnColor;
            
            // Set Icon
            const icon = document.getElementById('confirmIcon');
            if(btnText === 'Delete' || btnText === 'Reject') {
                icon.className = 'modal-header-icon delete-icon';
                icon.innerHTML = '<i class="fas fa-exclamation-triangle"></i>';
            } else if (btnText === 'Approve' || btnText === 'Mark Completed') {
                icon.className = 'modal-header-icon success-icon';
                icon.innerHTML = '<i class="fas fa-check"></i>';
            } else {
                icon.className = 'modal-header-icon question-icon';
                icon.innerHTML = '<i class="fas fa-question"></i>';
            }

            confirmCallback = callback;
            document.getElementById('confirmModal').classList.add('active');
        }

        document.getElementById('confirmBtnAction').addEventListener('click', () => {
            if(confirmCallback) confirmCallback();
            closeModal('confirmModal');
        });

        // --- VIEW BOOKING DETAILS ---
        const viewModal = document.getElementById('viewModal');

        function viewBooking(data) {
            document.getElementById('view-title').innerText = data.title;
            document.getElementById('view-name').innerText = data.name;
            document.getElementById('view-contact').innerText = data.contact;
            document.getElementById('view-email').innerText = data.email;
            document.getElementById('view-date').innerText = data.date;
            document.getElementById('view-request').innerText = data.request || "No details provided.";
            
            const statusEl = document.getElementById('view-status');
            statusEl.innerText = data.status;
            statusEl.className = 'status-badge status-' + data.status.toLowerCase();

            // HANDLE VALID ID DISPLAY
            const idContainer = document.getElementById('view-id-container');
            if(data.valid_id) {
                document.getElementById('view-valid-id').src = data.valid_id;
                document.getElementById('view-valid-id-link').href = data.valid_id;
                idContainer.style.display = 'block';
            } else {
                idContainer.style.display = 'none';
            }

            viewModal.classList.add('active');
        }

        function closeViewModal() { viewModal.classList.remove('active'); }
        window.onclick = function(event) { if (event.target === viewModal) closeViewModal(); }

        // --- REPLY MODAL LOGIC ---
        function openReplyModal(id, email) {
            document.getElementById('replyId').value = id;
            document.getElementById('replyToEmail').innerText = email;
            document.getElementById('replyModal').classList.add('active');
        }

        document.getElementById('replyForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const btn = e.target.querySelector('button');
            const originalText = btn.innerHTML;
            btn.disabled = true; btn.innerHTML = 'Sending...';

            try {
                const res = await fetch('reply_inquiry.php', { method: 'POST', body: formData });
                const text = await res.text();
                if(text.trim() === 'success') {
                    closeModal('replyModal');
                    showAlert('Sent!', 'Reply sent successfully!', 'success');
                } else {
                    showAlert('Error', 'Error sending email. Please try again.', 'error');
                }
            } catch(err) { 
                showAlert('Error', 'Request failed.', 'error'); 
            } finally { 
                btn.disabled = false; btn.innerHTML = originalText; 
            }
        });

        // --- UPDATE STATUS ---
        function updateStatus(id, action, btn) {
            let title = 'Confirm Action';
            let msg = `Are you sure you want to ${action} this appointment?`;
            let btnText = 'Confirm';
            let btnColor = '#cd853f';

            if(action === 'completed') {
                title = 'Mark Completed';
                msg = "Mark this appointment as Completed?";
                btnText = 'Mark Completed';
                btnColor = '#3b82f6'; 
            } else if (action === 'delete') {
                title = 'Move to Trash';
                msg = "Are you sure you want to move this to the trash?";
                btnText = 'Delete';
                btnColor = '#ef4444'; 
            } else if (action === 'approved') {
                title = 'Approve Appointment';
                btnText = 'Approve';
                btnColor = '#10b981'; 
            } else if (action === 'rejected') {
                title = 'Reject Appointment';
                btnText = 'Reject';
                btnColor = '#ef4444'; 
            }

            showConfirm(title, msg, btnText, btnColor, async () => {
                let originalContent = '';
                if(btn) {
                    btn.disabled = true;
                    originalContent = btn.innerHTML;
                    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
                }
                
                const formData = new FormData();
                formData.append('id', id);
                formData.append('action', action);
                try {
                    await fetch('update_booking.php', { method: 'POST', body: formData });
                    showAlert('Success', 'Status updated successfully.', 'success');
                } catch (error) {
                    showAlert('Error', 'An error occurred.', 'error');
                    if(btn) {
                        btn.disabled = false;
                        btn.innerHTML = originalContent;
                    }
                }
            });
        }

        // === NOTIFICATION & THEME LOGIC ===
        document.addEventListener('DOMContentLoaded', () => {
            
            // --- THEME TOGGLE LOGIC ---
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

            // --- NOTIFICATION LOGIC ---
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

        // --- CALENDAR ---
        let calendarInstance;
        function renderCalendar() {
            if (calendarInstance) { calendarInstance.render(); return; }
            const calendarEl = document.getElementById('calendar');
            calendarInstance = new FullCalendar.Calendar(calendarEl, {
                initialView: 'dayGridMonth',
                headerToolbar: { left: 'prev,next today', center: 'title', right: 'dayGridMonth,listWeek' },
                events: 'booking_events.php',
                eventColor: '#cd853f',
                height: 'auto'
            });
            calendarInstance.render();
        }
    </script>
</body>
</html>