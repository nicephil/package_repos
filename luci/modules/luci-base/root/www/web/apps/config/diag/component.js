(function () {
  'use strict'
  angular.module("oak.config")
    .component('configDiagView', {
      templateUrl: 'apps/config/diag/view.html',
      controller: function ( ConfigService, CommonService, $translate ) {
        var self = this;
        self.loading = false;           
        self.steps = [1, 2, 3, 4, 5];
        self.current_step = 0;        
        self.isDiagFinished = 0; // 0: Not finished. 1: Finished successfully. -1: Finished fail.
        self.stepInfo = [
          { step:1, name: "STATUS.DIAG.STEP1", fail: "STATUS.DIAG.STEP1_FAIL"},
          { step:2, name: "STATUS.DIAG.STEP2", fail: "STATUS.DIAG.STEP2_FAIL"},
          { step:3, name: "STATUS.DIAG.STEP3", fail: "STATUS.DIAG.STEP3_FAIL"},
          { step:4, name: "STATUS.DIAG.STEP4", fail: "STATUS.DIAG.STEP4_FAIL"},
          { step:5, name: "STATUS.DIAG.STEP5", fail: "STATUS.DIAG.STEP5_FAIL"}
        ];
        self.diagResult = "";      
        
        self.$onInit = function () {
          self.loading = true;          
          ConfigService.diag().then(function(res) {          
            self.current_step = res.step;          
            self.isDiagFinished = 0;
            self.diagResult = getTimeStamp() + $translate.instant('STATUS.DIAG.START') + "\n";
            self.proto = res.proto;
            self.startTime = Date.parse(new Date());
            queryDiag(self.current_step);
          }, function (error) { }).finally(function(){
            self.loading = false;
          })                  
        }

        function queryDiag(currentStep){        
          if(self.isDiagFinished === 0){
            ConfigService.querydiag(currentStep).then(function(res) {
              var stepInfo = getStepInfoByStep(currentStep);
              self.diagResult += getTimeStamp(Date.parse(new Date())) + (stepInfo ? $translate.instant(stepInfo.name) : "") + "\n";  
              self.isDiagFinished = res.step === -1 ? 1 : 0;
              queryDiag(res.step);                                 
            }, function (error) {
              var stepInfo = getStepInfoByStep(currentStep);
              self.diagResult += getTimeStamp(Date.parse(new Date())) + (stepInfo ? $translate.instant(stepInfo.fail) : "") + "\n";   
              self.isDiagFinished = -1;
            }).finally(function(){
              if(self.isDiagFinished === -1){
                self.diagResult += getTimeStamp(Date.parse(new Date())) + $translate.instant("STATUS.DIAG.END_FAIL") + "\n"; 
              }else if(self.isDiagFinished === 1){
                self.diagResult += getTimeStamp(Date.parse(new Date())) + $translate.instant("STATUS.DIAG.END_SUCCESS") + "\n";
              }
            })
          }
        }

        function getTimeStamp(timestamp){
          var blank = "       ";
          if(timestamp){
            var diff = Math.floor(( timestamp - self.startTime) / 1000);
            var seconds = diff % 60;
            var minutes = Math.floor((diff - seconds) / 60);
            return fillTimeWithZero(minutes) + ":" + fillTimeWithZero(seconds) + blank;
          }else{
            return "00:00" + blank;
          }
        }
        
        function fillTimeWithZero(timepart){
          if( timepart === 0 ){
            return "00";
          }else if( timepart < 10 ){
            return "0"+timepart;
          }else{
            return timepart;
          }
        }

        function getStepInfoByStep(step){
          var findStep = self.stepInfo.find(function(item){
            return item.step === step;
          });
          if(findStep){
            return findStep;
          }
        }

        self.next = function(){          
          redirectPage("config.status");
        }

        self.pre = function(){
          redirectPage("config.wan");
        }

        function redirectPage(page){          
          var error = "";
          if(self.isDiagFinished === -1){
            if(self.proto === 'pppoe'){
              if(self.currentStep < 3){
                error = $translate.instant('STATUS.DIAG.STEP_ERROR_PPPOE');
              }else{
                error = $translate.instant('STATUS.DIAG.STEP_ERROR_PPPOE_INTERNET');
              }
            }else{
              error = $translate.instant('STATUS.DIAG.STEP_ERROR_INTERNET');
            }
          }
          CommonService.navPage(page, { data: {
            status: self.isDiagFinished === 1 ? true : false,
            error : error
          }});
        }

      }
    })
})()