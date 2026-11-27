"""Offline desktop front end. No web server, network calls or sample execution."""
import sys, os, subprocess, threading, queue, json, webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXIT_LABEL = {0:'Completed — no high-priority findings', 2:'Review required (high findings or command error)', 3:'Partial scan / incomplete coverage', 4:'Partial scan + high-priority findings'}

def build_command(mode,path='',deep=False,output=None):
    exe = Path(sys.executable)
    if exe.name.lower() == 'pythonw.exe' and exe.with_name('python.exe').is_file():
        exe = exe.with_name('python.exe')
    cmd=[str(exe),'-m','sentinel',mode]
    if mode in ('file','directory') or (mode=='watch' and path):cmd.append(path)
    if mode=='host':
        cmd.append('--memory')
        if deep:cmd.extend(['--deep','--all-files','--max-files','25000','--total-mib','32768'])
    if mode=='directory':cmd.append('--all-files')
    if mode in ('file','directory','host','watch') and output:cmd.extend(['--output',str(output)])
    return cmd

def report_path(line, output):
    """Accept only existing JSON reports written to this run's output folder."""
    if line.startswith('JSON: '): candidate=line[6:]
    elif line.startswith('Watch: ') and ' | ' in line: candidate=line.rsplit(' | ',1)[1]
    elif line.startswith('Monitor stopped. Last report: '): candidate=line.split('Last report: ',1)[1]
    else: return None
    try:
        p=Path(candidate.strip()).resolve()
        if p.parent==output.resolve() and p.suffix=='.json' and p.name.startswith('sentinel-') and p.is_file():return p
    except (OSError,ValueError):pass
    return None

def main(smoke=False, smoke_file=None):
    import tkinter as tk
    from tkinter import ttk,filedialog,messagebox
    root=tk.Tk();root.title('SENTINEL | Local security workbench');root.geometry('1100x730');root.minsize(840,580)
    bg='#101722';panel='#182332';muted='#a6b5c9';fg='#e8eff7';accent='#72d9bd'
    root.configure(bg=bg);style=ttk.Style();style.theme_use('clam')
    style.configure('TFrame',background=bg);style.configure('Panel.TFrame',background=panel)
    style.configure('TLabel',background=bg,foreground=fg,font=('Segoe UI',10));style.configure('Muted.TLabel',foreground=muted);style.configure('Title.TLabel',font=('Segoe UI',24,'bold'),foreground=accent)
    style.configure('TButton',font=('Segoe UI',10),padding=(12,8),background=panel,foreground=fg,bordercolor='#36465b');style.map('TButton',background=[('active','#284054'),('disabled',bg)],foreground=[('disabled','#718198')]);style.configure('Accent.TButton',background='#216452',foreground='white')
    style.configure('TNotebook',background=bg,borderwidth=0);style.configure('TNotebook.Tab',background=panel,foreground=fg,padding=(15,8));style.map('TNotebook.Tab',background=[('selected','#304357')]);style.configure('Treeview',background=panel,fieldbackground=panel,foreground=fg,rowheight=27);style.configure('Treeview.Heading',background='#263648',foreground=fg);style.map('Treeview',background=[('selected','#365b70')]);style.configure('Horizontal.TProgressbar',background=accent,troughcolor=panel)
    outer=ttk.Frame(root,padding=18);outer.pack(fill='both',expand=True)
    header=ttk.Frame(outer);header.pack(fill='x');ttk.Label(header,text='SENTINEL',style='Title.TLabel').pack(side='left');ttk.Label(header,text='DESKTOP  /  OFFLINE',style='Muted.TLabel').pack(side='right');ttk.Label(outer,text='Local threat hunting • Read-only scanning • No cloud connection',style='Muted.TLabel').pack(anchor='w',pady=(0,14))
    status=tk.StringVar(value='Ready. Select a scan to begin.');summary=tk.StringVar(value='No scan yet. Findings are investigation leads, not proof of malware.');output=Path.home()/'SentinelReports';events=queue.Queue();state={'proc':None,'busy':False,'stopped':False,'report':None,'findings':{},'smoke_ok':False};buttons=[]
    actions=ttk.Frame(outer);actions.pack(fill='x',pady=(0,10))
    notebook=ttk.Notebook(outer);notebook.pack(fill='both',expand=True)
    result=ttk.Frame(notebook,padding=10);activity=ttk.Frame(notebook,padding=10);notebook.add(result,text='Findings');notebook.add(activity,text='Scan activity')
    ttk.Label(result,textvariable=summary,wraplength=790).pack(anchor='w',pady=(0,8))
    grid=ttk.Frame(result);grid.pack(fill='both',expand=True)
    tree=ttk.Treeview(grid,columns=('severity','confidence','finding','target'),show='headings',selectmode='browse');cols=[('severity','Severity',100),('confidence','Confidence',90),('finding','Finding',340),('target','Target',320)]
    for col,title,width in cols:tree.heading(col,text=title);tree.column(col,width=width,minwidth=70,stretch=col in ('finding','target'))
    scroll=ttk.Scrollbar(grid,command=tree.yview);tree.configure(yscrollcommand=scroll.set);scroll.pack(side='right',fill='y');tree.pack(fill='both',expand=True)
    for tag,color in [('critical','#ff8585'),('high','#ffad92'),('medium','#f8d38a'),('low','#9cc9ff'),('info',muted)]:tree.tag_configure(tag,foreground=color)
    ttk.Label(result,text='Evidence / limitations',style='Muted.TLabel').pack(anchor='w',pady=(9,4))
    def textbox(parent,height=8):
        frame=ttk.Frame(parent);frame.pack(fill='both',expand=True);t=tk.Text(frame,height=height,bg='#0b121c',fg=fg,insertbackground=fg,font=('Consolas',10),wrap='word',relief='flat',state='disabled',padx=9,pady=8);s=ttk.Scrollbar(frame,command=t.yview);t.configure(yscrollcommand=s.set);s.pack(side='right',fill='y');t.pack(fill='both',expand=True);return t
    details=textbox(result,6);log=textbox(activity,16)
    def write(widget,s,replace=False):
        widget.configure(state='normal');
        if replace:widget.delete('1.0','end')
        widget.insert('end',s);widget.see('1.0' if replace else 'end');widget.configure(state='disabled')
    def selection(_=None):
        ids=tree.selection()
        if ids and ids[0] in state['findings']:
            f=state['findings'][ids[0]];write(details, json.dumps(f,indent=2,ensure_ascii=True),True)
    tree.bind('<<TreeviewSelect>>',selection)
    def display(p):
        try:
            d=json.loads(p.read_text(encoding='utf-8'));stats=d.get('stats',{});findings=d.get('findings',[]);order={'critical':0,'high':1,'medium':2,'low':3,'info':4};findings=sorted(findings,key=lambda f:(order.get(f.get('severity'),9),-f.get('confidence',0)));high=sum(f.get('severity') in ('critical','high') for f in findings)
            summary.set(f"{stats.get('files_scanned','—')} files scanned   |   {len(findings)} findings   |   {high} high/critical   |   {stats.get('completion',stats.get('status','See report'))}")
            state['findings'].clear();tree.delete(*tree.get_children())
            for f in findings[:3000]:
                severity=f.get('severity','info');i=tree.insert('','end',values=(severity.upper(),f.get('confidence',''),f.get('title',''),f.get('target','')),tags=(severity,));state['findings'][i]=f
            note='\n'.join(str(x) for x in d.get('limitations',[])[:100]);write(details,(('Showing first 3000 findings. See full report.\n' if len(findings)>3000 else '')+'Coverage notes:\n'+note+'\n\nNo findings does not establish a clean system.'),True);state['report']=p;view_btn.configure(state='normal');notebook.select(result);return True
        except Exception as e:write(log,f'Unable to load report: {e}\n');return False
    def start(mode,path='',deep=False):
        if state['busy']:return
        state.update(busy=True,stopped=False,report=None,proc=None);state['findings'].clear();tree.delete(*tree.get_children());write(details,'',True);summary.set('Scanning…');status.set('Running '+mode+'…');write(log,'\n--- '+mode+' ---\n');notebook.select(activity);view_btn.configure(state='disabled');stop_btn.configure(state='normal');progress.start(12)
        for b in buttons:b.configure(state='disabled')
        def worker():
            found=None
            try:
                kw={'creationflags':subprocess.CREATE_NO_WINDOW} if os.name=='nt' else {'start_new_session':True}
                p=subprocess.Popen(build_command(mode,path,deep,output),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace',cwd=str(ROOT),env={**os.environ,'PYTHONUNBUFFERED':'1','PYTHONIOENCODING':'utf-8'},**kw);state['proc']=p
                if state['stopped']:p.terminate()
                for line in p.stdout:
                    events.put(('line',line));found=report_path(line,output) or found
                p.stdout.close();events.put(('done',(p.wait(),found,mode)))
            except Exception as e:events.put(('line',f'Launch error: {type(e).__name__}: {e}\n'));events.put(('done',(None,None,mode)))
        threading.Thread(target=worker,daemon=True).start()
    def choose(mode):
        p=filedialog.askopenfilename(title='Select a file to scan') if mode=='file' else filedialog.askdirectory(title='Select a local folder')
        if p:start(mode,p)
    for label,fn in [('Quick scan',lambda:start('host')),('Deep scan',lambda:start('host',deep=True)),('Scan file',lambda:choose('file')),('Scan folder',lambda:choose('directory')),('Monitor folder',lambda:choose('watch')),('Check setup',lambda:start('doctor'))]:
        b=ttk.Button(actions,text=label,command=fn,style='Accent.TButton' if label=='Scan file' else 'TButton');b.pack(side='left',padx=(0,5));buttons.append(b)
    bottom=ttk.Frame(outer);bottom.pack(fill='x',pady=(10,0));progress=ttk.Progressbar(bottom,mode='indeterminate',length=95);progress.pack(side='left',padx=(0,10));ttk.Label(bottom,textvariable=status,wraplength=500).pack(side='left')
    def stop():
        if state['busy'] and messagebox.askyesno('Stop','Stop now? A partial report may not be saved.'):
            state['stopped']=True;p=state['proc'];status.set('Stopping…');stop_btn.configure(state='disabled')
            if p and p.poll() is None:
                try:p.terminate()
                except OSError:pass
    def open_reports():
        try:
            output.mkdir(exist_ok=True)
            if os.name=='nt':os.startfile(str(output))
            else:messagebox.showinfo('Reports',str(output))
        except OSError as e:messagebox.showerror('Reports',str(e))
    def view_report():
        p=state['report'];hp=p.with_suffix('.html') if p else None
        if hp and hp.is_file():webbrowser.open(hp.as_uri())
        else:messagebox.showinfo('Report','No HTML report available. Use the report folder.')
    stop_btn=ttk.Button(bottom,text='Stop',command=stop,state='disabled');stop_btn.pack(side='right');ttk.Button(bottom,text='Report folder',command=open_reports).pack(side='right',padx=5);view_btn=ttk.Button(bottom,text='Open report',command=view_report,state='disabled');view_btn.pack(side='right')
    def poll():
        for _ in range(250):
            try:k,v=events.get_nowait()
            except queue.Empty:break
            if k=='line':write(log,v)
            else:
                code,p,mode=v;was_stopped=state['stopped'];state.update(proc=None,busy=False);progress.stop();stop_btn.configure(state='disabled')
                for b in buttons:b.configure(state='normal')
                ok=bool(p and display(p));label=('Stopped by user' if was_stopped else ('Setup check finished' if mode=='doctor' and code==0 else EXIT_LABEL.get(code,f'Error / exit {code}')))
                if not ok and mode!='doctor':label+=' — no report loaded';summary.set(label+'; see Scan activity.')
                status.set(label);write(log,f'\n{label}\n');state['smoke_ok']=ok
                if smoke_file:root.after(100,root.destroy)
        root.after(100,poll)
    def close():
        if state['busy']:messagebox.showinfo('Scan active','Stop the scan before closing.');return
        root.destroy()
    root.protocol('WM_DELETE_WINDOW',close);poll()
    if smoke_file:root.after(100,lambda:start('file',str(smoke_file)));root.after(15000,root.destroy)
    elif smoke:root.after(250,root.destroy)
    root.mainloop();return 0 if not smoke_file or state['smoke_ok'] else 3
