"""GUI 样式常量。"""

# 颜色
BG_MAIN = "#f0f0f0"
BG_TREE = "#ffffff"
BG_LOG = "#1e1e1e"
FG_LOG_INFO = "#d4d4d4"
FG_LOG_WARN = "#e5c07b"
FG_LOG_ERROR = "#f44747"
FG_LOG_SYSTEM = "#569cd6"
FG_TITLE = "#333333"

# 字体
FONT_TITLE = ("Microsoft YaHei UI", 11, "bold")
FONT_TREE = ("Microsoft YaHei UI", 9)
FONT_LABEL = ("Microsoft YaHei UI", 9)
FONT_ENTRY = ("Consolas", 9)
FONT_LOG = ("Consolas", 9)
FONT_BUTTON = ("Microsoft YaHei UI", 9)
FONT_STATUS = ("Microsoft YaHei UI", 8)

# 间距
PAD_OUTER = 10
PAD_INNER = 5
PAD_FORM = 3
SECTION_GAP = 12

# 尺寸
TREE_MIN_WIDTH = 180
LOG_MIN_HEIGHT = 180
WINDOW_WIDTH = 1100
WINDOW_HEIGHT = 720
WINDOW_MIN_WIDTH = 900
WINDOW_MIN_HEIGHT = 600

# 日志级别标记
LOG_TAGS = {
    "INFO": FG_LOG_INFO,
    "WARN": FG_LOG_WARN,
    "ERROR": FG_LOG_ERROR,
    "SYSTEM": FG_LOG_SYSTEM,
}
