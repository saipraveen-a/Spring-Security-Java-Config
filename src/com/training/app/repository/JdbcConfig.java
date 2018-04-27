package com.training.app.repository;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;

@Configuration
public class JdbcConfig {
  @Bean
  public DataSource dataSource() {

    DriverManagerDataSource ret = new DriverManagerDataSource();
    ret.setDriverClassName("com.mysql.jdbc.Driver");
    ret.setUsername("root");
    ret.setPassword("admin");
    ret.setUrl("jdbc:mysql://localhost:3306/springdemo");

    return ret;
  }
}