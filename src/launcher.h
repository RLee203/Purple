#pragma once

#include "apps.h"

void launcherEnter();
void launcherDraw();
void launcherNextMode();
void launcherNextHardwareProfile();
void launcherMoveSelection(int delta);
void launcherOpenTeamApps();
void launcherShowModePicker();
bool launcherShowingModePicker();
TeamMode launcherCurrentMode();
AppId launcherCurrentApp();
