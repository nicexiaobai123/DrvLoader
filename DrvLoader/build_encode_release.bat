set "projectpath=%cd%"
cd ../
set "preProjectpath=%cd%"
cd %projectpath%
set "SignFullPath=%preProjectpath%/x64/Release/CheatRw.sys"
Build.exe %SignFullPath%