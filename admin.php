<?php
session_start();
include 'config.php';

if (!isset($_SESSION['username']) || !isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    header("Location: index.php");
    exit();
}

$stats = [
    'total_art' => 0,
    'pending_req' => 0,
    'approved_req' => 0,
    'completed_app' => 0,
    'cancelled_app' => 0,
    'unread_inquiries' => 0,
    'users' => 0
];

// 1. Artworks
$res = mysqli_query($conn, "SELECT COUNT(*) as total FROM artworks");
if ($res) $stats['total_art'] = mysqli_fetch_assoc($res)['total'];

// 2. Reservation Stats
$stats['pending_req'] = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as total FROM bookings WHERE status = 'pending' AND deleted_at IS NULL"))['total'];
$stats['approved_req'] = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as total FROM bookings WHERE status = 'approved' AND deleted_at IS NULL"))['total'];
$stats['completed_app'] = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as total FROM bookings WHERE status = 'completed' AND deleted_at IS NULL"))['total'];
$stats['cancelled_app'] = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as total FROM bookings WHERE (status = 'rejected' OR status = 'cancelled') AND deleted_at IS NULL"))['total'];

// 3. Inquiries
$res = mysqli_query($conn, "SELECT COUNT(*) as total FROM inquiries WHERE status != 'replied'");
if ($res) $stats['unread_inquiries'] = mysqli_fetch_assoc($res)['total'];

// 4. Users
$res = mysqli_query($conn, "SELECT COUNT(*) as total FROM users WHERE role != 'admin'");
if ($res) $stats['users'] = mysqli_fetch_assoc($res)['total'];

// --- RECENT BOOKINGS ---
$recent_bookings = [];
$sql_recent = "SELECT b.*, a.title as art_title, u.username as collector_name
               FROM bookings b 
               LEFT JOIN artworks a ON b.artwork_id = a.id 
               LEFT JOIN users u ON b.user_id = u.id
               WHERE b.deleted_at IS NULL 
               ORDER BY b.created_at DESC LIMIT 5";
$result_recent = mysqli_query($conn, $sql_recent);
while ($row = mysqli_fetch_assoc($result_recent)) { $recent_bookings[] = $row; }

// --- CHART DATA ---
$selectedYear = date('Y');
$months = [];
$bookingsData = array_fill(0, 12, 0);
for ($m = 1; $m <= 12; $m++) { $months[] = date("M", mktime(0, 0, 0, $m, 1)); }

$query_chart = "SELECT MONTH(created_at) AS month, COUNT(*) AS total FROM bookings WHERE deleted_at IS NULL AND YEAR(created_at) = $selectedYear GROUP BY MONTH(created_at)";
$result_chart = mysqli_query($conn, $query_chart);
while ($row = mysqli_fetch_assoc($result_chart)) { $bookingsData[$row['month'] - 1] = (int) $row['total']; }

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
    <title>Dashboard | ManCave Admin</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Nunito+Sans:wght@400;600;700;800&family=Playfair+Display:wght@600;700&family=Pacifico&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.3.0/dist/chart.umd.min.js"></script>
    
    <style>
        /* =========================================
           INLINED ADMIN THEME (Uniform Style)
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
            --purple: #8b5cf6;
            
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

        /* === DASHBOARD CARDS === */
        .stats-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 25px; margin-bottom: 40px;
        }
        .stat-card {
            background: var(--card-bg); padding: 25px; border-radius: var(--radius-soft);
            box-shadow: 0 5px 15px var(--shadow-color); border: 1px solid var(--border-color);
            display: flex; align-items: center; gap: 20px; transition: transform 0.3s ease;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-icon {
            width: 60px; height: 60px; border-radius: 12px; display: flex;
            align-items: center; justify-content: center; font-size: 1.5rem; flex-shrink: 0;
        }
        /* Icon Colors */
        .stat-icon.purple { background: rgba(139, 92, 246, 0.1); color: var(--purple); }
        .stat-icon.orange { background: rgba(245, 158, 11, 0.1); color: var(--orange); }
        .stat-icon.blue { background: rgba(59, 130, 246, 0.1); color: var(--blue); }
        .stat-icon.red { background: rgba(239, 68, 68, 0.1); color: var(--red); }

        .stat-details h3 { font-size: 1.8rem; font-weight: 800; margin: 0; color: var(--text-main); line-height: 1; }
        .stat-details span { color: var(--text-muted); font-size: 0.9rem; font-weight: 600; margin-top: 5px; display: block; }

        /* === DASHBOARD LAYOUT === */
        .dashboard-layout { display: grid; grid-template-columns: 2fr 1fr; gap: 30px; }
        .col-chart { grid-column: span 1; }
        .col-side { grid-column: span 1; }
        .col-full { grid-column: 1 / -1; }

        .card {
            background: var(--card-bg); border-radius: var(--radius-soft);
            box-shadow: 0 5px 15px var(--shadow-color); padding: 30px;
            border: 1px solid var(--border-color); height: 100%;
        }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; }
        .card-header h3 { font-size: 1.2rem; font-weight: 800; color: var(--text-main); margin: 0; }
        
        .chart-filter {
            padding: 8px 12px; border: 1px solid var(--border-color); border-radius: 8px;
            background: var(--input-bg); color: var(--text-main); font-family: var(--font-main);
        }
        .chart-container { position: relative; height: 300px; width: 100%; }

        /* Summary Card */
        .summary-card h3 { font-size: 1.2rem; font-weight: 800; margin-bottom: 25px; color: var(--text-main); }
        .summary-item {
            display: flex; justify-content: space-between; align-items: center;
            padding: 15px 0; border-bottom: 1px solid var(--border-color);
        }
        .summary-item:last-child { border-bottom: none; }
        .summary-item .label { display: flex; align-items: center; gap: 10px; color: var(--text-muted); font-weight: 600; }
        .summary-item .value { font-weight: 800; color: var(--text-main); font-size: 1.1rem; }
        .dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
        .dot.approved { background: var(--green); }
        .dot.completed { background: var(--blue); }
        .dot.cancelled { background: var(--red); }

        /* Tables */
        .table-responsive { overflow-x: auto; }
        .styled-table { width: 100%; border-collapse: collapse; }
        .styled-table th {
            text-align: left; padding: 15px 20px; background: var(--bg-body);
            color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px;
            border-bottom: 1px solid var(--border-color); font-weight: 700;
        }
        .styled-table td { padding: 15px 20px; border-bottom: 1px solid var(--border-color); color: var(--text-main); vertical-align: middle; font-size: 0.95rem; }
        .styled-table tr:hover { background: rgba(0,0,0,0.02); }
        
        .id-badge { background: var(--bg-body); padding: 4px 8px; border-radius: 4px; font-weight: 700; font-size: 0.85rem; color: var(--text-muted); border: 1px solid var(--border-color); }
        
        .user-cell { display: flex; align-items: center; gap: 10px; }
        .user-avatar-sm { width: 32px; height: 32px; background: var(--accent); color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 0.8rem; }
        
        .status-badge { padding: 5px 12px; border-radius: 50px; font-size: 0.75rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; }
        .status-pending { background: rgba(245, 158, 11, 0.1); color: var(--orange); }
        .status-approved { background: rgba(59, 130, 246, 0.1); color: var(--blue); }
        .status-completed { background: rgba(16, 185, 129, 0.1); color: var(--green); }
        .status-cancelled { background: rgba(239, 68, 68, 0.1); color: var(--red); }
        
        .view-all { font-size: 0.85rem; color: var(--accent); font-weight: 700; }

        /* Notifications Dropdown */
        .notif-wrapper { position: relative; }
        .notif-bell .dot { position: absolute; top: 0; right: 0; background: var(--red); color: white; font-size: 0.6rem; font-weight: 700; border-radius: 50%; min-width: 16px; height: 16px; display: flex; align-items: center; justify-content: center; border: 2px solid var(--card-bg); }
        .notif-dropdown { display: none; position: absolute; right: -10px; top: 60px; width: 320px; background: var(--card-bg); border-radius: 12px; box-shadow: 0 15px 40px rgba(0,0,0,0.15); border: 1px solid var(--border-color); z-index: 1100; overflow: hidden; }
        .notif-dropdown.active { display: block; }
        .notif-header { padding: 15px; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; font-weight: 700; color: var(--text-main); background: var(--bg-body); }
        .notif-list { max-height: 300px; overflow-y: auto; }
        .notif-item { padding: 15px; border-bottom: 1px solid var(--border-color); cursor: pointer; transition: 0.2s; color: var(--text-main); }
        .notif-item:hover { background: var(--bg-body); }
        .notif-item.unread { border-left: 3px solid var(--accent); background: rgba(205, 133, 63, 0.05); }
        .no-notif { padding: 20px; text-align: center; color: var(--text-muted); font-style: italic; }
        .small-btn { background: none; border: none; color: var(--accent); font-weight: 700; font-size: 0.75rem; cursor: pointer; text-transform: uppercase; }

        @media (max-width: 1024px) {
            .dashboard-layout { grid-template-columns: 1fr; }
            .sidebar { width: 80px; padding: 20px 10px; }
            .sidebar-logo span:not(.logo-main), .logo-bottom, .sidebar-nav span, .sidebar-footer span { display: none; }
            .logo-main { font-size: 1.5rem; transform: rotate(0); }
            .sidebar-nav a { justify-content: center; padding: 15px; }
            .sidebar-nav a:hover { transform: none; }
            .main-content { margin-left: 80px; width: calc(100% - 80px); }
            .stats-grid { grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }
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
                <li class="active"><a href="admin.php"><i class="fas fa-home"></i> <span>Dashboard</span></a></li>
                <li><a href="reservations.php"><i class="fas fa-calendar-check"></i> <span>Appointments</span></a></li>
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
                <h1><?php echo $greeting; ?>, Admin! 👋</h1>
                <p>Overview of gallery activities and requests.</p>
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

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon purple"><i class="fas fa-image"></i></div>
                <div class="stat-details">
                    <h3><?php echo $stats['total_art']; ?></h3>
                    <span>Total Artworks</span>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-icon orange"><i class="fas fa-clock"></i></div>
                <div class="stat-details">
                    <h3><?php echo $stats['pending_req']; ?></h3>
                    <span>Pending Bookings</span>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-icon" style="background: rgba(239, 68, 68, 0.1); color: var(--red);"><i class="fas fa-envelope"></i></div>
                <div class="stat-details">
                    <h3><?php echo $stats['unread_inquiries']; ?></h3>
                    <span>New Inquiries</span>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-icon blue"><i class="fas fa-user-friends"></i></div>
                <div class="stat-details">
                    <h3><?php echo $stats['users']; ?></h3>
                    <span>Active Customers</span>
                </div>
            </div>
        </div>

        <div class="dashboard-layout">
            
            <div class="col-chart">
                <div class="card chart-card">
                    <div class="card-header">
                        <h3>Reservation Analytics</h3>
                        <select class="chart-filter">
                            <option>This Year</option>
                        </select>
                    </div>
                    <div class="chart-container">
                        <canvas id="monthlyBookingsChart"></canvas>
                    </div>
                </div>
            </div>

            <div class="col-side">
                <div class="card summary-card">
                    <div class="card-header">
                        <h3>Booking Summary</h3>
                    </div>
                    <div class="summary-item">
                        <span class="label"><span class="dot approved"></span> Approved</span>
                        <span class="value"><?php echo $stats['approved_req']; ?></span>
                    </div>
                    <div class="summary-item">
                        <span class="label"><span class="dot completed"></span> Completed</span>
                        <span class="value"><?php echo $stats['completed_app']; ?></span>
                    </div>
                    <div class="summary-item">
                        <span class="label"><span class="dot cancelled"></span> Cancelled</span>
                        <span class="value"><?php echo $stats['cancelled_app']; ?></span>
                    </div>
                </div>
            </div>

            <div class="col-full">
                <div class="card table-card">
                    <div class="card-header">
                        <h3>Recent Appointments</h3>
                        <a href="reservations.php" class="view-all">View All</a>
                    </div>
                    <div class="table-responsive">
                        <table class="styled-table">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Customer</th>
                                    <th>Service / Artwork</th>
                                    <th>Scheduled Date</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (empty($recent_bookings)): ?>
                                    <tr><td colspan="5" class="text-center" style="padding:20px;">No recent activity found.</td></tr>
                                <?php else: ?>
                                    <?php foreach ($recent_bookings as $row): 
                                        $statusClass = strtolower($row['status']);
                                        if($statusClass == 'rejected') $statusClass = 'cancelled';
                                    ?>
                                    <tr>
                                        <td><span class="id-badge">#<?php echo $row['id']; ?></span></td>
                                        <td>
                                            <div class="user-cell">
                                                <div class="user-avatar-sm"><?php echo strtoupper(substr($row['collector_name'] ?? 'G', 0, 1)); ?></div>
                                                <span><?php echo htmlspecialchars($row['collector_name'] ?? 'Guest'); ?></span>
                                            </div>
                                        </td>
                                        <td><?php echo htmlspecialchars($row['service'] ?: $row['art_title']); ?></td>
                                        <td><?php echo date('M d, Y', strtotime($row['preferred_date'])); ?></td>
                                        <td><span class="status-badge status-<?php echo $statusClass; ?>"><?php echo ucfirst($row['status']); ?></span></td>
                                    </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

        </div>
    </main>

    <script>
        // Chart.js Configuration
        let myChart; 

        function initChart(theme) {
            const ctx = document.getElementById('monthlyBookingsChart').getContext('2d');
            
            // Determine colors based on theme
            const isDark = theme === 'dark';
            const gridColor = isDark ? 'rgba(255, 255, 255, 0.1)' : '#f0f0f0';
            const textColor = isDark ? '#a0a0a0' : '#666';
            
            // Gradient
            let gradient = ctx.createLinearGradient(0, 0, 0, 400);
            gradient.addColorStop(0, 'rgba(205, 133, 63, 0.2)');
            gradient.addColorStop(1, 'rgba(205, 133, 63, 0)');

            if (myChart) myChart.destroy(); 

            myChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: <?php echo json_encode($months); ?>,
                    datasets: [{
                        label: 'Reservations',
                        data: <?php echo json_encode($bookingsData); ?>,
                        backgroundColor: gradient,
                        borderColor: '#cd853f',
                        borderWidth: 2,
                        pointBackgroundColor: isDark ? '#1e1e1e' : '#fff',
                        pointBorderColor: '#cd853f',
                        pointRadius: 4,
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { 
                            beginAtZero: true, 
                            grid: { borderDash: [5, 5], color: gridColor },
                            ticks: { color: textColor } 
                        },
                        x: { 
                            grid: { display: false },
                            ticks: { color: textColor }
                        }
                    }
                }
            });
        }

        // === NOTIFICATION & THEME LOGIC ===
        document.addEventListener('DOMContentLoaded', () => {
            
            // --- THEME TOGGLE LOGIC ---
            const themeToggleBtn = document.getElementById('themeToggle');
            const themeIcon = themeToggleBtn.querySelector('i');
            
            // Initial Chart Load
            const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
            if(currentTheme === 'dark') themeIcon.classList.replace('fa-moon', 'fa-sun');
            initChart(currentTheme);

            themeToggleBtn.addEventListener('click', () => {
                const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
                
                if (isDark) {
                    document.documentElement.removeAttribute('data-theme');
                    localStorage.setItem('adminTheme', 'light');
                    themeIcon.classList.replace('fa-sun', 'fa-moon');
                    initChart('light'); // Update Chart
                } else {
                    document.documentElement.setAttribute('data-theme', 'dark');
                    localStorage.setItem('adminTheme', 'dark');
                    themeIcon.classList.replace('fa-moon', 'fa-sun');
                    initChart('dark'); // Update Chart
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
    </script>
</body>
</html>