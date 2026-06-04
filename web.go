package main

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

//go:embed public/*
var embeddedFS embed.FS

var tmpl = template.Must(template.New("").Parse(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{{.Title}}</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
    a{color:#818cf8;text-decoration:none}a:hover{text-decoration:underline}
    .header{background:#1e293b;border-bottom:1px solid #334155;padding:0 24px;position:sticky;top:0;z-index:10}
    .header-inner{max-width:1400px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;height:60px}
    .brand{display:flex;align-items:center;gap:12px}
    .brand-icon{font-size:24px}
    .brand h1{font-size:18px;font-weight:700}
    .brand span{font-size:11px;color:#64748b}
    .header-stats{display:flex;gap:24px}
    .stat{text-align:center}
    .stat-num{font-size:20px;font-weight:700;color:#818cf8}
    .stat-label{font-size:11px;color:#64748b}
    .container{max-width:1400px;margin:0 auto;padding:24px;display:grid;grid-template-columns:260px 1fr;gap:24px;min-height:calc(100vh - 60px)}
    .sidebar{background:#1e293b;border-radius:12px;padding:20px;border:1px solid #334155;height:fit-content;position:sticky;top:84px}
    .sidebar h3{font-size:12px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:12px}
    .year-list{list-style:none}
    .year-item a{display:flex;justify-content:space-between;align-items:center;padding:8px 12px;border-radius:8px;color:#94a3b8;font-size:14px;transition:all .15s}
    .year-item a:hover{background:#334155;color:#e2e8f0;text-decoration:none}
    .year-item.active a{background:#312e81;color:#a5b4fc;font-weight:600}
    .year-count{font-size:11px;background:#334155;padding:2px 8px;border-radius:9999px}
    .main{display:flex;flex-direction:column;gap:16px}
    .filter-bar{background:#1e293b;border-radius:12px;padding:16px;border:1px solid #334155;display:flex;flex-wrap:wrap;gap:12px;align-items:center}
    .search-input{flex:1;min-width:200px;background:#0f172a;border:1px solid #334155;border-radius:8px;padding:10px 14px;color:#e2e8f0;font-size:14px;outline:none}
    .search-input:focus{border-color:#6366f1}
    .filter-tabs{display:flex;gap:4px}
    .tab{padding:8px 16px;border-radius:8px;font-size:13px;font-weight:500;cursor:pointer;border:1px solid #334155;background:transparent;color:#94a3b8;transition:all .15s}
    .tab:hover{background:#334155;color:#e2e8f0}
    .tab.active{background:#6366f1;color:white;border-color:#6366f1}
    .cve-count{font-size:12px;color:#64748b}
    .cve-grid{display:flex;flex-direction:column;gap:8px}
    .cve-card{background:#1e293b;border-radius:12px;padding:16px;border:1px solid #334155;transition:border-color .15s}
    .cve-card:hover{border-color:#6366f1}
    .cve-header{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:8px}
    .cve-id{font-size:15px;font-weight:700;color:#a5b4fc;font-family:monospace}
    .cve-id a{color:#a5b4fc}
    .cve-meta{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
    .badge{font-size:11px;padding:3px 10px;border-radius:9999px;font-weight:500}
    .badge-new{background:#052e16;color:#86efac;border:1px solid #166534}
    .badge-update{background:#1c1400;color:#fde047;border:1px solid #713f12}
    .badge-year{background:#1e293b;color:#64748b;border:1px solid #334155}
    .cve-desc{font-size:13px;color:#94a3b8;line-height:1.5;margin-bottom:12px}
    .cve-footer{display:flex;justify-content:space-between;align-items:center}
    .cve-stats{display:flex;gap:16px}
    .cve-stat{display:flex;align-items:center;gap:4px;font-size:12px;color:#64748b}
    .cve-source{font-size:12px;color:#475569}
    .empty{text-align:center;padding:60px 20px;color:#64748b}
    .empty-icon{font-size:48px;margin-bottom:16px}
    .footer{border-top:1px solid #1e293b;padding:24px;text-align:center;font-size:12px;color:#475569}
    .footer a{color:#475569}
    @media(max-width:768px){.container{grid-template-columns:1fr}.sidebar{display:none}}
  </style>
</head>
<body>
  <header class="header">
    <div class="header-inner">
      <div class="brand">
        <span class="brand-icon">&#128269;</span>
        <div>
          <h1>Poc-Monitor</h1>
          <span>&#21994;&#33021;&#24773;&#25253; &#183; &#28431;&#27934; POC &#30417;&#25511;</span>
        </div>
      </div>
      <div class="header-stats">
        <div class="stat"><div class="stat-num">{{.TotalCVE}}</div><div class="stat-label">&#25910;&#24405; CVE</div></div>
        <div class="stat"><div class="stat-num">{{.TodayNew}}</div><div class="stat-label">&#20170;&#26085;&#26032;&#22686;</div></div>
        <div class="stat"><div class="stat-num">{{.TodayUpdate}}</div><div class="stat-label">&#20170;&#26085;&#26356;&#26032;</div></div>
      </div>
    </div>
  </header>
  <div class="container">
    <aside class="sidebar">
      <h3>&#128193; &#25353;&#24180;&#20221;&#27983;&#35272;</h3>
      <ul class="year-list">
        <li class="year-item{{if eq .SelectedYear \"\"}} active{{end}}">
          <a href="/?q={{.Query}}&tab={{.Tab}}">&#20840;&#37096;&#24180;&#20221;</a>
        </li>
        {{range .Years}}
        <li class="year-item{{if eq $.SelectedYear .Name}} active{{end}}">
          <a href="/?year={{.Name}}&q={{$.Query}}&tab={{$.Tab}}">{{.Name}}<span class="year-count">{{.Count}}</span></a>
        </li>
        {{end}}
      </ul>
    </aside>
    <main class="main">
      <div class="filter-bar">
        <input class="search-input" id="searchInput" placeholder="&#128269; &#25628;&#32034; CVE / &#20179;&#24211;&#21517; / &#25551;&#36848;..." value="{{.Query}}">
        <div class="filter-tabs">
          <button class="tab{{if eq .Tab \"all\"}} active{{end}}" onclick="setTab('all')">&#20840;&#37096;</button>
          <button class="tab{{if eq .Tab \"new\"}} active{{end}}" onclick="setTab('new')">&#128994; &#26032;&#22686;</button>
          <button class="tab{{if eq .Tab \"update\"}} active{{end}}" onclick="setTab('update')">&#128259; &#26356;&#26032;</button>
        </div>
        <span class="cve-count">&#20849; <strong>{{.VisibleCount}}</strong> &#26465;</span>
      </div>
      <div class="cve-grid">
        {{range .Items}}
        <div class="cve-card">
          <div class="cve-header">
            <div>
              <div class="cve-meta">
                <span class="cve-id"><a href="{{.HtmlUrl}}" target="_blank">{{.CVEId}}</a></span>
                {{if .IsNew}}<span class="badge badge-new">&#128994; &#26032;&#22686;</span>{{end}}
                {{if .IsUpdate}}<span class="badge badge-update">&#128259; &#26356;&#26032;</span>{{end}}
                <span class="badge badge-year">{{.Year}}</span>
              </div>
            </div>
            <div class="cve-stats">
              <span class="cve-stat">&#11088; {{.Stars}}</span>
              <span class="cve-stat">&#127837; {{.Forks}}</span>
            </div>
          </div>
          <p class="cve-desc">{{.Description}}</p>
          <div class="cve-footer">
            <span class="cve-source">&#128100; {{.Owner}} &#183; {{.UpdatedAt}}</span>
            <a href="{{.HtmlUrl}}" target="_blank" style="font-size:12px;">View &#8594;</a>
          </div>
        </div>
        {{else}}
        <div class="empty"><div class="empty-icon">&#128269;</div><p>&#26410;&#25214;&#21040;&#21305;&#37197;&#30340; CVE&#32467;&#26524;</p></div>
        {{end}}
      </div>
    </main>
  </div>
  <footer class="footer">
    <p>&#25968;&#25454;&#26469;&#28304;&#65306;GitHub &#183; <a href="https://github.com/adminlove520/Poc-Monitor">&#11088; Star on GitHub</a></p>
  </footer>
  <script>
    const params = new URLSearchParams(window.location.search);
    let currentTab = params.get('tab') || 'all';
    let currentYear = params.get('year') || '';
    let currentQuery = params.get('q') || '';
    function setTab(tab) { currentTab = tab; updateURL(); }
    function updateURL() {
      const url = new URL(window.location);
      url.searchParams.set('tab', currentTab);
      if (currentYear) url.searchParams.set('year', currentYear);
      if (currentQuery) url.searchParams.set('q', currentQuery);
      window.location = url;
    }
    document.getElementById('searchInput').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') { currentQuery = this.value; updateURL(); }
    });
  </script>
</body>
</html>`))

type PageData struct {
	Title        string
	Years        []YearGroup
	SelectedYear string
	Items        []CVEItem
	Query        string
	Tab          string
	TotalCVE     int
	TodayNew     int
	TodayUpdate  int
	VisibleCount int
}

type YearGroup struct {
	Name  string
	Count int
}

type CVEItem struct {
	CVEId       string
	Year        string
	Description string
	Stars       int
	Forks       int
	Owner       string
	HtmlUrl     string
	UpdatedAt   string
	IsNew       bool
	IsUpdate    bool
}

type Server struct {
	rootDir string
}

func (s *Server) root() string {
	if s.rootDir != "" {
		return s.rootDir
	}
	return GetCurrentDirectory()
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	query := r.URL.Query().Get("q")
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "all"
	}
	yearFilter := r.URL.Query().Get("year")
	root := s.root()

	todayLog := loadDateLog(root, time.Now().Format("2006-01-02"))
	newMap := make(map[int64]bool)
	updateMap := make(map[int64]bool)
	for _, it := range todayLog.New {
		newMap[it.Id] = true
	}
	for _, it := range todayLog.Update {
		updateMap[it.Id] = true
	}

	yearCounts := make(map[string]int)
	var items []CVEItem

	entries, _ := os.ReadDir(root)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "20") {
			continue
		}
		yearName := entry.Name()
		yearDir := filepath.Join(root, yearName)
		yearEntries, _ := os.ReadDir(yearDir)
		for _, ye := range yearEntries {
			if !strings.HasPrefix(ye.Name(), "CVE") || !strings.HasSuffix(ye.Name(), ".json") {
				continue
			}
			yearCounts[yearName]++
			if yearFilter != "" && yearFilter != yearName {
				continue
			}

			var cveItems []Item
			fpath := filepath.Join(yearDir, ye.Name())
			ReadJsonFile(fpath, &cveItems)

			for _, it := range cveItems {
				cveId := strings.TrimSuffix(ye.Name(), ".json")
				desc := it.Description
				if desc == "" {
					desc = it.Name
				}
				if desc == "" {
					desc = "&#26080;&#25551;&#36848;"
				}

				isNew := newMap[it.Id]
				isUpdate := updateMap[it.Id]

				if tab == "new" && !isNew {
					continue
				}
				if tab == "update" && !isUpdate {
					continue
				}

				if query != "" {
					lower := strings.ToLower(query)
					found := strings.Contains(strings.ToLower(cveId), lower) ||
						strings.Contains(strings.ToLower(desc), lower) ||
						strings.Contains(strings.ToLower(it.Name), lower) ||
						strings.Contains(strings.ToLower(it.Owner.Login), lower)
					if !found {
						continue
					}
				}

				items = append(items, CVEItem{
					CVEId:       cveId,
					Year:        yearName,
					Description: desc,
					Stars:       it.StargazersCount,
					Forks:       it.ForksCount,
					Owner:       it.Owner.Login,
					HtmlUrl:     it.HtmlUrl,
					UpdatedAt:   it.UpdatedAt.Format("2006-01-02"),
					IsNew:       isNew,
					IsUpdate:    isUpdate,
				})
			}
		}
	}

	var years []YearGroup
	for name, count := range yearCounts {
		years = append(years, YearGroup{Name: name, Count: count})
	}
	sort.Slice(years, func(i, j int) bool { return years[i].Name > years[j].Name })

	title := "Poc-Monitor &#183; &#28431;&#27934; POC &#30417;&#25511;"
	if yearFilter != "" {
		title = yearFilter + " &#24180; CVE &#183; Poc-Monitor"
	}

	data := PageData{
		Title:        title,
		Years:        years,
		SelectedYear: yearFilter,
		Items:        items,
		Query:        query,
		Tab:          tab,
		TotalCVE:     len(items),
		TodayNew:     len(todayLog.New),
		TodayUpdate:  len(todayLog.Update),
		VisibleCount: len(items),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

func loadDateLog(rootDir, date string) DateLog {
	logPath := fmt.Sprintf("%s/%s/%s.json", rootDir, LogFilePath, date)
	var log DateLog
	ReadJsonFile(logPath, &log)
	return log
}
