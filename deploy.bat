git apply github.patch && ^
invoke build && ^
git reset --hard && ^
git checkout master && ^
xcopy /s /Y .\output . && ^
git add . && ^
git checkout --orphan t && ^
git add -u && ^
git commit -m "Regenerate site" && ^
call git branch -D master && ^
call git branch -m master && ^
git push -f origin master && ^
git checkout dev