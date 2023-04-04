#docker build -f Dockerfile_pred -t sage_predict .
#docker run -it -v $PWD/output_pred:/home/out sage_predict:latest

source /Users/ionbabalau/uni/thesis/SAGE/.venv/bin/activate
cp docker_stuff/spdfa-config.ini /Users/ionbabalau/uni/thesis/FlexFringe/ini/spdfa-config.ini
cp docker_stuff/spdfa-config-sinks.ini /Users/ionbabalau/uni/thesis/FlexFringe/ini/spdfa-config-sinks.ini
python3 src/prediction.py
