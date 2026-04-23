package com.guohao.demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

@SpringBootApplication
public class DemoApplication implements CommandLineRunner {
    @Value("${app.name:unknown}")
    private String appName;

    @Value("${app.port:0}")
    private int appPort;

    public static void main(String[] args) {
        ConfigurableApplicationContext ctx = SpringApplication.run(DemoApplication.class, args);
        int exitCode = SpringApplication.exit(ctx);
        System.exit(exitCode);
    }

    @Override
    public void run(String... args) {
        System.out.println("Loaded from encrypted config:");
        System.out.println("app.name=" + appName);
        System.out.println("app.port=" + appPort);
    }
}
