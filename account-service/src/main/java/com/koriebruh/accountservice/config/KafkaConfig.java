package com.koriebruh.accountservice.config;

import com.koriebruh.accountservice.event.AccountEvent;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class KafkaConfig {

    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Bean
    public ProducerFactory<String, AccountEvent> producerFactory() {
        Map<String, Object> config = new HashMap<>();
        config.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        config.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);

        config.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG,
                org.apache.kafka.common.serialization.ByteArraySerializer.class);

        config.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true);
        config.put(ProducerConfig.ACKS_CONFIG, "all");
        config.put(ProducerConfig.RETRIES_CONFIG, 3);
        config.put(ProducerConfig.MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION, 1);

        DefaultKafkaProducerFactory<String, AccountEvent> factory =
                new DefaultKafkaProducerFactory<>(config);


        factory.setValueSerializer(new org.apache.kafka.common.serialization.Serializer<>() {
            private final com.fasterxml.jackson.databind.ObjectMapper mapper =
                    new com.fasterxml.jackson.databind.ObjectMapper()
                            .registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule())
                            .disable(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

            @Override
            public byte[] serialize(String topic, AccountEvent data) {
                try {
                    return mapper.writeValueAsBytes(data);
                } catch (Exception e) {
                    throw new RuntimeException("Failed to serialize AccountEvent", e);
                }
            }
        });

        return factory;
    }

    @Bean
    public KafkaTemplate<String, AccountEvent> kafkaTemplate() {
        return new KafkaTemplate<>(producerFactory());
    }
}