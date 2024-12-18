start_time=$(date +%s)

sudo docker-compose down -v
sudo docker-compose up --remove-orphans

end_time=$(date +%s)
duration=$((end_time - start_time))
echo "Total compose.shexecution time: ${duration} seconds"