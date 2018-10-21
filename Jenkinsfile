node {
    def app

    stage('Clone repository') {
        checkout scm
    }

    stage('Test and Build image') {
        app = docker.build("eschudt/jwt-auth")
    }

    stage('Integration Test') {
        app.inside {
            sh 'echo "Tests passed"'
        }
    }

    stage('Push image') {
        /* Finally, we'll push the image with two tags:
         * First, the incremental build number from Jenkins
         * Second, the 'latest' tag.
         * Pushing multiple tags is cheap, as all the layers are reused. */
        docker.withRegistry('https://registry.hub.docker.com', 'docker-hub-credentials') {
            app.push("${env.BUILD_NUMBER}")
            app.push("latest")
        }
    }

    stage('Deploy - Dev') {
        sh "/root/deploy.sh /root/public_server.txt jwt-auth ${env.BUILD_NUMBER} 2"
        sh 'echo "Deployed to Dev"'
    }
}
