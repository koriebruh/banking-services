package com.koriebruh.authservice.config;

import com.koriebruh.authservice.event.AuthEvent;
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
    public ProducerFactory<String, AuthEvent> producerFactory() {
        Map<String, Object> config = new HashMap<>();
        config.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        config.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);

        // Spring Kafka 4.0 deprecated their own JsonSerializer
        // Use kafka-clients native serializer instead
        config.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG,
                org.apache.kafka.common.serialization.ByteArraySerializer.class);

        config.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true);
        config.put(ProducerConfig.ACKS_CONFIG, "all");
        config.put(ProducerConfig.RETRIES_CONFIG, 3);
        config.put(ProducerConfig.MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION, 1);

        DefaultKafkaProducerFactory<String, AuthEvent> factory =
                new DefaultKafkaProducerFactory<>(config);

        // Set Jackson serializer directly on the factory
        factory.setValueSerializer(new org.apache.kafka.common.serialization.Serializer<>() {
            private final com.fasterxml.jackson.databind.ObjectMapper mapper =
                    new com.fasterxml.jackson.databind.ObjectMapper()
                            .registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule())
                            .disable(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

            @Override
            public byte[] serialize(String topic, AuthEvent data) {
                try {
                    return mapper.writeValueAsBytes(data);
                } catch (Exception e) {
                    throw new RuntimeException("Failed to serialize AuthEvent", e);
                }
            }
        });

        return factory;
    }

    @Bean
    public KafkaTemplate<String, AuthEvent> kafkaTemplate() {
        return new KafkaTemplate<>(producerFactory());
    }
}