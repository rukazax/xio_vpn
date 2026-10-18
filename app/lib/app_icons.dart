import 'package:flutter/material.dart';

import 'core.dart';
import 'l10n.dart';

final appIconVariants = [
  for (final color in ['green', 'white'])
    for (final background in ['dark', 'clear'])
      for (final angle in [0, 90, 180, 270]) '${color}_${background}_$angle',
];

class AppIconPicker extends StatefulWidget {
  final AppStore store;
  const AppIconPicker({super.key, required this.store});
  @override
  State<AppIconPicker> createState() => _AppIconPickerState();
}

class _AppIconPickerState extends State<AppIconPicker> {
  String? selected;
  bool busy = false;
  @override
  void initState() {
    super.initState();
    native
        .invokeMethod<String>('getAppIcon')
        .then((value) {
          if (mounted) setState(() => selected = value);
        })
        .catchError((Object _) {
          if (mounted) setState(() => selected = appIconVariants.first);
        });
  }

  Future<void> select(String value) async {
    setState(() => busy = true);
    try {
      await native.invokeMethod<void>('setAppIcon', value);
      if (mounted) setState(() => selected = value);
    } catch (_) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: LText('Не удалось выполнить действие')),
        );
      }
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      for (final color in ['green', 'white'])
        for (final background in ['dark', 'clear']) ...[
          Text(
            '${tr(context, color == 'green' ? 'Бирюзовая' : 'Белая')} · ${tr(context, background == 'dark' ? 'тёмный фон' : 'прозрачный фон')}',
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              for (final angle in [0, 90, 180, 270])
                Builder(
                  builder: (context) {
                    final id = '${color}_${background}_$angle';
                    return SizedBox(
                      width: 64,
                      child: Column(
                        children: [
                          Semantics(
                            label:
                                '${tr(context, color == 'green' ? 'Бирюзовая' : 'Белая')}, $angle°, ${tr(context, background == 'dark' ? 'тёмный фон' : 'прозрачный фон')}',
                            selected: selected == id,
                            button: true,
                            child: InkWell(
                              key: ValueKey('icon-$id'),
                              onTap: busy ? null : () => select(id),
                              borderRadius: BorderRadius.circular(14),
                              child: Container(
                                padding: const EdgeInsets.all(4),
                                decoration: BoxDecoration(
                                  color: const Color(0xff555d65),
                                  borderRadius: BorderRadius.circular(14),
                                  border: Border.all(
                                    width: 2,
                                    color: selected == id
                                        ? Theme.of(context).colorScheme.primary
                                        : Colors.transparent,
                                  ),
                                ),
                                child: Image.asset(
                                  'assets/icons/$id.png',
                                  width: 52,
                                  height: 52,
                                ),
                              ),
                            ),
                          ),
                          Text('$angle°'),
                        ],
                      ),
                    );
                  },
                ),
            ],
          ),
          const SizedBox(height: 12),
        ],
    ],
  );
}
