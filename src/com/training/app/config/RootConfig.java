/**
 * 
 */
package com.training.app.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(basePackages = {"com.training.app.service", "com.training.app.repository"})
public class RootConfig {

}
