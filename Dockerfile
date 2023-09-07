# Don't forget about "$ xhost +" before running container
FROM ubuntu
 
ENV TZ=Europe/Moscow
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Installing linux libs
RUN apt-get update && apt-get install -y \
   git 

# Installing GO
RUN apt-get install -y \
   golang-go

ENV PATH=/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Installing Python
RUN apt-get install -y \
   python3 \
   python3-pip

# 
COPY ./requirements.txt /code/requirements.txt
COPY ./bin/cyclonedx-gomod /code/cyclonedx-gomod

# 
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

# 
COPY ./app /code/app

WORKDIR /code
# 
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "80"]
