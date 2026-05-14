#!/bin/bash
cloc . --include-lang=Go,TypeScript,Rust \
       --include-ext=go,ts,tsx,rs \
       --exclude-dir=node_modules,dist,build,out,.next,.turbo,.vite,target,vendor,.git,.github,bin,obj,debug,release,coverage,public,static,assets,tmp,temp,logs,docs,.idea,.vscode,.vs
