@echo off
setlocal enabledelayedexpansion

set AGGREGATION=ip

pushd %~dp0

mkdir cmd
mkdir svg

(
echo.^<!DOCTYPE html^>
echo.^<html^>
echo.    ^<head^>
echo.        ^<meta charset="utf-8" /^>
echo.        ^<meta name="viewport" content="width=device-width" /^>
echo.        ^<title^>View SVG^</title^>
echo.
echo.        ^<script charset="utf-8"^>
echo.            window.addEventListener^('DOMContentLoaded', ^(event^) ^=^> {
echo.                let s = document.getElementById^("s"^);
echo.                let p = document.getElementById^("p"^);
echo.                let h = function^(event^) {
echo.                    let o = document.getElementById^("o"^)
echo.                    if ^(s.value==""^) {o.data=""} else {o.data = "svg/"+s.value+"_"+p.value+".svg"}
echo.                }
echo.                s.addEventListener^("change", h^)
echo.                p.addEventListener^("change", h^)
echo.            }^)
echo.            
echo.        ^</script^>
echo.    ^</head^>
echo.    ^<body^>
echo.        ^<form^>
echo.            ^<select id="s" style="font-size:xx-large"^>
echo.            ^<option value=""^>^</option^>
) > view_svg.html

for %%i in (*.json) do (
    @set a=%%i
    @set a=!a:.json=!
    echo !a!
    echo ^<option value="!a!"^>!a!^</option^> >> view_svg.html
    wfw -i %%i --format svg --svg-dir svg --svg-name-format %%_{protocol}.svg -a %AGGREGATION%
    echo chcp 65001 >cmd\!a!.bat
    wfw -i %%i --format cmd -a %AGGREGATION% >>cmd\!a!.bat
)

(
echo.            ^</select^>
echo.            
echo.            ^<select id="p" style="font-size:xx-large"^>
echo.            ^<option value="TCP" selected^>TCP^</option^>
echo.            ^<option value="UDP"^>UDP^</option^>
echo.            ^</select^>
echo.        ^</form^>
echo.
echo.        ^<object type="image/svg+xml" data="" id="o"^>
echo.            Not Selected
echo.        ^</object^>
echo.    ^</body^>
echo.^</html^>
) >> view_svg.html
