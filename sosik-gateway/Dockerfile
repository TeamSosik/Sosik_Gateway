# Use OpenJDK 11 as the base image
FROM openjdk:17

LABEL maintainer="minutaurus"

ARG JAR_FILE=build/libs/SoSikGateway-0.0.1-SNAPSHOT.jar

COPY ${JAR_FILE} /SoSikGateway-0.0.1-SNAPSHOT.jar

ENTRYPOINT ["java","-jar","/SoSikGateway-0.0.1-SNAPSHOT.jar"]

EXPOSE 5056

