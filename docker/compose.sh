start_time=$(date +%s)

sudo docker-compose down -v
sudo docker-compose up --remove-orphans | tee log.txt

end_time=$(date +%s)
duration=$((end_time - start_time))
echo "Total compose.sh execution time: ${duration} seconds" | tee -a log.txt