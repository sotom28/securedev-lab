// Pipeline CI/CD de SecureDev Tickets (OCY1102 EV3).
// Etapas: construcción, revisiones de seguridad, despliegue de pruebas y escaneo ZAP.
// Los informes quedan archivados en cada ejecución como evidencia para la auditoría.
pipeline {
    agent any

    options {
        timestamps()
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }

    environment {
        // Red que crea docker compose (name: securedev-estudiante en compose.yaml)
        COMPOSE_NETWORK = 'securedev-estudiante_default'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                sh 'mkdir -p reports'
            }
        }

        stage('Build') {
            steps {
                sh 'docker build -t securedev-tickets:${BUILD_NUMBER} .'
            }
        }

        stage('Auditoría de dependencias (pip-audit)') {
            steps {
                // Sin bind mounts: el contenedor recibe el archivo con docker cp.
                sh '''
                    cid=$(docker create python:3.11-slim sh -c "pip install -q pip-audit && pip-audit -r /requirements.txt")
                    docker cp requirements.txt "$cid":/requirements.txt
                    docker start -a "$cid" > reports/pip-audit.txt 2>&1
                    rc=$?
                    cat reports/pip-audit.txt
                    docker rm "$cid" > /dev/null
                    exit $rc
                '''
            }
        }

        stage('Análisis estático (Bandit)') {
            steps {
                // Solo informa: no detiene el pipeline.
                sh '''
                    cid=$(docker create python:3.11-slim sh -c "pip install -q bandit && bandit /app.py -f txt")
                    docker cp app.py "$cid":/app.py
                    docker start -a "$cid" > reports/bandit.txt 2>&1 || true
                    cat reports/bandit.txt
                    docker rm "$cid" > /dev/null
                '''
            }
        }

        stage('Deploy (entorno de pruebas)') {
            steps {
                sh '''
                    docker compose up -d --build
                    for i in $(seq 1 20); do
                        if docker compose exec -T app python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"; then
                            echo "Aplicación lista"; exit 0
                        fi
                        sleep 2
                    done
                    echo "La aplicación no respondió a tiempo"; exit 1
                '''
            }
        }

        stage('OWASP ZAP baseline') {
            steps {
                // -I: las advertencias no detienen el pipeline; el informe se archiva igualmente.
                sh '''
                    docker rm -f zap-scan > /dev/null 2>&1 || true
                    docker run --name zap-scan --network "$COMPOSE_NETWORK" -u root \
                        ghcr.io/zaproxy/zaproxy:stable \
                        sh -c "mkdir -p /zap/wrk && zap-baseline.py -t http://app:8000 -r zap.html -w zap.md -I" \
                        || true
                    docker cp zap-scan:/zap/wrk/zap.html reports/zap.html
                    docker cp zap-scan:/zap/wrk/zap.md reports/zap.md
                    docker rm zap-scan > /dev/null
                '''
            }
        }
    }

    post {
        always {
            sh 'docker rm -f zap-scan > /dev/null 2>&1 || true'
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
    }
}
