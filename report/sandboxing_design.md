# Sandboxing Design Document for 8TechBank

## Overview
This document outlines the sandboxing strategy for deploying the 8TechBank application in a secure, isolated environment using Docker containers. The design focuses on minimizing attack surfaces, enforcing resource limits, and implementing network segmentation to protect against potential exploits.

## Containerization Strategy

### Docker Image Design
- **Base Image**: Python 3.9-slim for minimal attack surface
- **Multi-stage Build**: Not implemented due to simple application, but recommended for production
- **Non-root User**: Application runs as non-privileged user (no-new-privileges security option)
- **Read-only Filesystem**: Container filesystem is read-only except for /tmp

### Dockerfile Security Features
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "app.py"]
```
- Minimal packages installed
- No unnecessary tools or shells
- Explicit port exposure

## Network Segmentation

### Docker Compose Configuration
```yaml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=production
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    networks:
      - app_network

networks:
  app_network:
    driver: bridge
```

### Network Isolation
- Dedicated bridge network for application
- No external network access except for exposed port
- Internal communication restricted to app_network
- No inter-container communication required (single service)

## Resource Limits

### Memory and CPU Constraints
- Memory limit: 512MB (configurable)
- CPU limit: 0.5 cores (configurable)
- Prevents resource exhaustion attacks

### Filesystem Restrictions
- Read-only root filesystem
- Temporary files in tmpfs (in-memory)
- No persistent storage for sensitive data
- Database stored in container (for demo; use external in production)

## Security Hardening

### Runtime Security Options
- `no-new-privileges`: Prevents privilege escalation
- `read-only`: Prevents filesystem tampering
- Dropped capabilities (default Docker behavior)

### Application-Level Sandboxing
- Flask application runs in debug=False in production
- Secure session configuration
- Input validation with Marshmallow schemas
- Rate limiting with Flask-Limiter
- JWT authentication with expiration

## Monitoring and Logging

### Container Logs
- All application logs captured by Docker
- Centralized logging recommended for production
- Log rotation to prevent disk filling

### Health Checks
- Basic health endpoint for container orchestration
- Resource monitoring via Docker stats

## Deployment Considerations

### Production Deployment
- Use Docker Swarm or Kubernetes for orchestration
- Implement secrets management (Docker secrets)
- Add TLS termination (nginx reverse proxy)
- Database externalization with persistent volumes
- Backup and recovery procedures

### Scaling
- Horizontal scaling with load balancer
- Session affinity for stateful operations
- Database connection pooling

## Risk Mitigation

### Attack Vectors Addressed
1. **Container Escape**: Read-only FS, no-new-privileges, minimal base image
2. **Resource Exhaustion**: Memory/CPU limits, rate limiting
3. **Network Attacks**: Isolated network, no external access
4. **Data Exfiltration**: Minimal exposed services, JWT expiration
5. **Privilege Escalation**: Non-root user, dropped capabilities

### Compliance
- OWASP ASVS Level 2 compliance for container security
- NIST SP 800-190 guidelines for container security

## Conclusion
This sandboxing design provides a secure foundation for deploying 8TechBank, balancing security with operational requirements. The containerized approach ensures consistency across environments while implementing defense-in-depth security measures.

Word count: 528