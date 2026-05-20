content = open('main.py', encoding='utf-8').read()

old = "from flask import Flask, request, jsonify, render_template, session, redirect, url_for, Response"
new = "from flask import Flask, request, jsonify, render_template, session, redirect, Response"
content = content.replace(old, new)

old2 = """from database import (
    add_log, get_logs, get_logs_today, get_sessions, delete_session,"""
new2 = """from database import (
    add_log, get_logs_today, get_sessions, delete_session,"""
content = content.replace(old2, new2)

open('main.py', 'w', encoding='utf-8').write(content)
print('Done! Dead imports removed.')
