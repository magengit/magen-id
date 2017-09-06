'use strict';
angular.module('ui.ace', []).constant('uiAceConfig', {}).directive('uiAce', [
	'uiAceConfig', '$window', 
	function (uiAceConfig, $window) {
		if (angular.isUndefined(window.ace)) {
			throw new Error('ui-ace need ace to work... (o rly?)');
		}
		return {
			restrict: 'EA',
			require: '?ngModel',
			link: function (scope, elm, attrs, ngModel) {
				var options, opts, acee, session, onChange;
				options = uiAceConfig.ace || {};
				opts = angular.extend({}, options, scope.$eval(attrs.uiAce));
				acee = window.ace.edit(elm[0]);
				session = acee.getSession();
				onChange = function (callback) {
					return function (e) {
						var newValue = session.getValue();
						if (newValue !== scope.$eval(attrs.value) && !scope.$$phase && !scope.$root.$$phase) {
							if (angular.isDefined(ngModel)) {
								scope.$apply(function () {
									ngModel.$setViewValue(newValue);
								});
							}
							if (angular.isDefined(callback)) {
								scope.$apply(function () {
									if (angular.isFunction(callback)) {
										callback(e, acee);
									} else {
										throw new Error('ui-ace use a function as callback.');
									}
								});
							}
						}
					};
				};
				if (angular.isDefined(opts.showGutter)) {
					acee.renderer.setShowGutter(opts.showGutter);
				}
				if (angular.isDefined(opts.useWrapMode)) {
					session.setUseWrapMode(opts.useWrapMode);
				}
				if (angular.isFunction(opts.onLoad)) {
					opts.onLoad(acee);
				}
				if (angular.isString(opts.theme)) {
					acee.setTheme('ace/theme/' + opts.theme);
				}
				if (angular.isString(opts.mode)) {
					session.setMode('ace/mode/' + opts.mode);
				}
				if (typeof opts.showPrintMargin === 'boolean') {
					acee.setShowPrintMargin(opts.showPrintMargin);
				}
				if(typeof opts.minLines === 'number' && typeof opts.maxLines === 'number') {
					acee.setOptions({
						minLines: opts.minLines,
						maxLines: opts.maxLines
					});
				}
				attrs.$observe('readonly', function (value) {
					acee.setReadOnly(value === 'true');
				});
				if (angular.isDefined(ngModel)) {
					ngModel.$formatters.push(function (value) {
						if (angular.isUndefined(value) || value === null) {
							return '';
						} else if (angular.isObject(value) || angular.isArray(value)) {
							throw new Error('ui-ace cannot use an object or an array as a model');
						}
						return value;
					});
					ngModel.$render = function () {
						//Set flag to ignore cursor change events during redraw
						redrawing = true;
						session.setValue(ngModel.$viewValue);
						redrawing = false;
						//Set cursor position from IndexReference
						var cursorPos = session.getDocument().indexToPosition(window.controllerScope.currentPage.indexRef.index);
						acee.selection.moveCursorToPosition(cursorPos);
					};
				}

				//ZR mod: track cursor changes in IndexReference
				//Flag to suppress change events while rendering
				var redrawing = false;
				acee.getSelection().on('changeCursor', function(event) {
					if(angular.isDefined(ngModel) && !redrawing) {
						var newPos = session.getDocument().positionToIndex(acee.selection.getCursor());
						window.controllerScope.currentPage.indexRef.index = newPos;
					}
				});

				session.on('change', onChange(opts.onChange));
				elm.on('$destroy', function () {
					acee.session.$stopWorker();
					acee.destroy();
				});
				//Handle window resize
				var offset = parseInt(attrs.heightoffset);
				if(offset) {
					var updateHeight = function() {
						elm.css({
							'height': String(window.innerHeight - offset) + 'px'
						});
						acee.resize(true);
					};
					updateHeight();
					angular.element($window).bind('resize', updateHeight);
				}
			}
		};
	}
]);
