node {
  stage 'Load shared libaries'

  def openshift, git
  def version='v3.0.0'
  fileLoader.withGit('https://git.aurora.skead.no/scm/ao/aurora-pipeline-scripts.git', version) {
    openshift = fileLoader.load('openshift/openshift');
    git = fileLoader.load('git/git');
  }

  stage 'Checkout'
  checkout scm

  stage 'Bygg OpenShift-image'
  def commitId = git.getCommitId()
  openshift.buildImageWithCredentials('wrench', commitId, "github")
}
