package com.example.SoSikGateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class SoSikGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(SoSikGatewayApplication.class, args);
	}

}
