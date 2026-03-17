"use client";

import { useState, useCallback } from "react";
import CodeMirror from "@uiw/react-codemirror";
import { javascript } from "@codemirror/lang-javascript";
import { python } from "@codemirror/lang-python";
import { html } from "@codemirror/lang-html";
import { css } from "@codemirror/lang-css";
import { php } from "@codemirror/lang-php";
import { java } from "@codemirror/lang-java";
import { oneDark } from "@codemirror/theme-one-dark";
import { Extension } from "@codemirror/state";

const LANGUAGES: { value: string; label: string; ext: () => Extension }[] = [
  { value: "javascript", label: "JavaScript", ext: () => javascript({ jsx: true }) },
  { value: "typescript", label: "TypeScript", ext: () => javascript({ typescript: true }) },
  { value: "python", label: "Python", ext: python },
  { value: "php", label: "PHP", ext: php },
  { value: "java", label: "Java", ext: java },
  { value: "html", label: "HTML", ext: html },
  { value: "css", label: "CSS", ext: css },
];

const SAMPLE_CODE: Record<string, string> = {
  javascript: `// Example: Vulnerable Node.js/Express app
const express = require('express');
const mysql = require('mysql');
const app = express();

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password123',  // Hardcoded credential
  database: 'users'
});

app.get('/user', (req, res) => {
  const userId = req.query.id;
  // SQL Injection vulnerability
  const query = \`SELECT * FROM users WHERE id = \${userId}\`;
  db.query(query, (err, results) => {
    res.send(results);
  });
});

app.get('/profile', (req, res) => {
  const name = req.query.name;
  // XSS vulnerability
  res.send(\`<h1>Hello \${name}</h1>\`);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // No rate limiting, no CSRF token
  db.query(\`SELECT * FROM users WHERE username='\${username}' AND password='\${password}'\`, (err, results) => {
    if (results.length > 0) {
      req.session.user = results[0];
      res.redirect('/dashboard');
    }
  });
});`,
  python: `# Example: Vulnerable Flask app
from flask import Flask, request, render_template_string
import sqlite3
import subprocess
import pickle
import base64

app = Flask(__name__)
SECRET_KEY = "mysecretkey123"  # Hardcoded secret

@app.route('/search')
def search():
    query = request.args.get('q', '')
    conn = sqlite3.connect('app.db')
    # SQL Injection
    cursor = conn.execute(f"SELECT * FROM products WHERE name LIKE '%{query}%'")
    results = cursor.fetchall()
    # XSS - unsanitized template rendering
    return render_template_string(f"<h1>Results for {query}</h1><ul>{''.join(f'<li>{r}</li>' for r in results)}</ul>")

@app.route('/run')
def run_command():
    cmd = request.args.get('cmd')
    # Command Injection
    output = subprocess.check_output(cmd, shell=True)
    return output

@app.route('/load')
def load_data():
    data = request.args.get('data')
    # Insecure deserialization
    obj = pickle.loads(base64.b64decode(data))
    return str(obj)`,
};

interface CodeEditorProps {
  onAnalyze: (code: string, language: string) => void;
  isStreaming: boolean;
}

export default function CodeEditor({ onAnalyze, isStreaming }: CodeEditorProps) {
  const [language, setLanguage] = useState("javascript");
  const [code, setCode] = useState(SAMPLE_CODE["javascript"]);

  const handleLanguageChange = useCallback((lang: string) => {
    setLanguage(lang);
    if (SAMPLE_CODE[lang]) {
      setCode(SAMPLE_CODE[lang]);
    }
  }, []);

  const langConfig = LANGUAGES.find((l) => l.value === language);
  const extensions = langConfig ? [langConfig.ext()] : [];

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center justify-between px-4 py-3 bg-slate-800 border-b border-slate-700">
        <div className="flex items-center gap-3">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Language</span>
          <select
            value={language}
            onChange={(e) => handleLanguageChange(e.target.value)}
            className="bg-slate-700 text-slate-200 text-sm rounded px-2 py-1 border border-slate-600 focus:outline-none focus:border-cyan-500"
          >
            {LANGUAGES.map((l) => (
              <option key={l.value} value={l.value}>{l.label}</option>
            ))}
          </select>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500">{code.split("\n").length} lines</span>
          <button
            onClick={() => setCode("")}
            className="text-xs text-slate-400 hover:text-slate-200 px-2 py-1 rounded hover:bg-slate-700 transition-colors"
          >
            Clear
          </button>
        </div>
      </div>

      {/* Editor */}
      <div className="flex-1 overflow-hidden">
        <CodeMirror
          value={code}
          height="100%"
          theme={oneDark}
          extensions={extensions}
          onChange={(val) => setCode(val)}
          style={{ height: "100%", fontSize: "13px" }}
        />
      </div>

      {/* Analyze Button */}
      <div className="px-4 py-3 bg-slate-800 border-t border-slate-700">
        <button
          onClick={() => onAnalyze(code, language)}
          disabled={isStreaming || !code.trim()}
          className="w-full flex items-center justify-center gap-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-700 disabled:text-slate-500 text-white font-semibold py-2.5 px-4 rounded-lg transition-colors"
        >
          {isStreaming ? (
            <>
              <span className="inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              분석 중...
            </>
          ) : (
            <>
              <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              취약점 분석 시작
            </>
          )}
        </button>
      </div>
    </div>
  );
}
