rm -rf run.log
python test.py >> run.log 2>&1
cat run.log
